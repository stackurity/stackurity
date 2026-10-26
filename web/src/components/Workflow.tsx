import { useEffect, useState, type FormEvent } from "react";
import {
  api,
  IGNORE_REASONS,
  type ActionResult,
  type DirectoryUser,
  type Finding,
  type FindingActionName,
  type FindingActionRequest,
  type IgnoreExpiry,
  type IgnoreReason,
  type IgnoreRequest,
  type IgnoreScope,
  type List,
  type Team,
} from "../api";
import { useAuth } from "../auth";
import { useAction, useExceptionMaxDays, useLoad } from "../hooks";
import { absTime, plural, relTime } from "../format";
import { IGNORE_REASON_LABEL } from "./Badge";
import { ErrorBox, Notice } from "./ui";

/** A deadline with relative time; overdue ones are flagged in text, not just colour. */
export function DueDate({ iso, overdue, label }: { iso: string | null | undefined; overdue?: boolean; label?: string }) {
  if (!iso) return <span className="muted">—</span>;
  const past = new Date(iso).getTime() < Date.now();
  const over = overdue ?? past;
  return (
    <time dateTime={iso} title={`${label ? label + ": " : ""}${absTime(iso)}`} className={`due${over ? " due-over" : ""}`}>
      {over ? `overdue ${relTime(iso).replace(/ ago$/, "")}` : `due ${relTime(iso)}`}
    </time>
  );
}

export function Assignee({ email, team }: { email?: string; team?: string }) {
  if (!email && !team) return <span className="muted">unassigned</span>;
  return (
    <span>
      {email}
      {email && team ? <br /> : null}
      {team && <span className={email ? "muted small" : undefined}>team {team}</span>}
    </span>
  );
}

export type ActionTarget =
  | { type: "finding"; id: number }
  | { type: "bulk"; ids: number[] }
  | { type: "incident"; id: number }
  /** Every open issue of a fix group (at most GROUP_ACTION_MAX), sent as bulk actions. */
  | { type: "group"; id: string; count: number };

/** Largest fix group whose issues can be changed at once from the fix page. */
export const GROUP_ACTION_MAX = 2000;

/** Applies a bulk action to every open finding of a fix group, 500 at a time. */
async function groupAction(groupId: string, req: FindingActionRequest): Promise<ActionResult> {
  const ids: number[] = [];
  for (let offset = 0; offset < GROUP_ACTION_MAX; offset += 500) {
    const page = await api.get<List<Finding>>("/findings", { fix_group: groupId, limit: 500, offset });
    ids.push(...page.items.map((f) => f.id));
    if (page.items.length < 500 || ids.length >= page.total) break;
  }
  let applied = 0;
  const failed: string[] = [];
  for (let i = 0; i < ids.length; i += 500) {
    const r = await api.post<ActionResult>("/findings/actions", { ...req, ids: ids.slice(i, i + 500) });
    applied += r.applied;
    failed.push(...(r.failed ?? []));
  }
  return { applied, failed };
}

function isoDate(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}
function addDays(n: number): Date {
  const d = new Date();
  d.setDate(d.getDate() + n);
  return d;
}
/** End of the chosen local day, clamped to just under maxDays from now (server limit). */
function untilFromDate(day: string, maxDays: number): string {
  const end = new Date(`${day}T23:59:59`);
  const limit = addDays(maxDays);
  limit.setMinutes(limit.getMinutes() - 5);
  return (end.getTime() > limit.getTime() ? limit : end).toISOString();
}

type Panel = null | "assign" | "comment" | "suppress" | "ignore" | "request";

const LABELS: Record<FindingActionName, string> = {
  acknowledge: "Acknowledged",
  start: "Marked in progress",
  reset: "Reset to new",
  assign: "Assigned",
  comment: "Comment added",
  suppress: "Snoozed",
  accept_risk: "Risk accepted",
  ignore: "Ignored",
  reopen: "Reopened",
};

/** The issues a request to ignore is about: finding ids, or a fix's open issues. */
async function requestTarget(target: ActionTarget): Promise<{ finding_ids?: number[]; fix_group?: string }> {
  switch (target.type) {
    case "finding":
      return { finding_ids: [target.id] };
    case "bulk":
      return { finding_ids: target.ids };
    case "group":
      return { fix_group: target.id };
    case "incident": {
      const d = await api.get<{ findings: Finding[] }>(`/incidents/${target.id}`);
      return { finding_ids: (d.findings ?? []).filter((f) => f.status === "open").map((f) => f.id) };
    }
  }
}

/**
 * Workflow buttons for one finding, a selection, or every open finding of an
 * incident or fix. Engineer: acknowledge/start/reset/assign/comment. Security+:
 * snooze (until a date or until a fix ships), ignore (reason, scope, expiry)
 * and reopen. Everyone below security can ask to ignore; security and admin
 * users decide in the approval inbox.
 */
export function FindingActions({
  target,
  state,
  onDone,
  compact,
  initialPanel,
}: {
  target: ActionTarget;
  /** Opens this form first (e.g. from a "Snooze" link on Home). */
  initialPanel?: "assign" | "suppress" | "accept_risk" | "ignore";
  /** Current state for a single finding, to hide actions that cannot apply. */
  state?: string;
  onDone: () => void;
  compact?: boolean;
}) {
  const { can, me } = useAuth();
  const engineer = can("engineer");
  const security = can("security");
  const act = useAction();
  const first: Panel = initialPanel === "accept_risk" || initialPanel === "ignore" ? (security ? "ignore" : "request") : (initialPanel ?? null);
  const [panel, setPanel] = useState<Panel>(first && (engineer || first === "request") ? first : null);
  const [result, setResult] = useState<string | null>(null);
  const [failures, setFailures] = useState<string[]>([]);

  if (!me?.workspace) return null;

  const closed = state === "suppressed" || state === "risk_accepted";
  const count = target.type === "bulk" ? target.ids.length : target.type === "group" ? target.count : null;

  const send = async (req: FindingActionRequest) => {
    setResult(null);
    setFailures([]);
    const r = await act.run(() => {
      if (target.type === "finding") return api.post<ActionResult>(`/findings/${target.id}/actions`, req);
      if (target.type === "incident") return api.post<ActionResult>(`/incidents/${target.id}/actions`, req);
      if (target.type === "group") return groupAction(target.id, req);
      return api.post<ActionResult>("/findings/actions", { ...req, ids: target.ids });
    });
    if (r) {
      const n = r.applied;
      setResult(`${LABELS[req.action]}${target.type === "finding" ? "" : `: ${n} finding${n === 1 ? "" : "s"} changed`}.`);
      setFailures(r.failed ?? []);
      setPanel(null);
      onDone();
    }
  };

  const ask = async (spec: IgnoreFormValue) => {
    setResult(null);
    setFailures([]);
    const r = await act.run(async () => {
      const t = await requestTarget(target);
      if (t.finding_ids && t.finding_ids.length === 0) throw new Error("There is no open issue to ignore.");
      return api.post<IgnoreRequest>("/ignore-requests", { ...t, ...spec });
    });
    if (r) {
      setResult(`Sent to your security team for approval (request #${r.id}, ${plural(r.finding_ids.length, "issue")}).`);
      setPanel(null);
    }
  };

  const toggle = (p: Panel) => {
    act.clear();
    setPanel(panel === p ? null : p);
  };

  return (
    <div className="workflow-actions">
      <div className="btn-group" role="group" aria-label={count !== null ? `Actions for ${count} ${target.type === "group" ? "issues in this fix" : "selected findings"}` : "Finding actions"}>
        {engineer && !closed && (
          <>
            {state !== "acknowledged" && (
              <button type="button" className="btn btn-sm" disabled={act.pending} onClick={() => send({ action: "acknowledge" })}>
                Acknowledge
              </button>
            )}
            {state !== "in_progress" && (
              <button type="button" className="btn btn-sm" disabled={act.pending} onClick={() => send({ action: "start" })}>
                Start work
              </button>
            )}
            {state && state !== "new" && (
              <button type="button" className="btn btn-sm" disabled={act.pending} onClick={() => send({ action: "reset" })}>
                Reset to new
              </button>
            )}
          </>
        )}
        {engineer && (
          <button type="button" className="btn btn-sm" aria-expanded={panel === "assign"} onClick={() => toggle("assign")}>
            Assign…
          </button>
        )}
        {engineer && !compact && (
          <button type="button" className="btn btn-sm" aria-expanded={panel === "comment"} onClick={() => toggle("comment")}>
            Comment…
          </button>
        )}
        {security && !closed && (
          <>
            <button type="button" className="btn btn-sm" aria-expanded={panel === "suppress"} onClick={() => toggle("suppress")}>
              Snooze…
            </button>
            <button type="button" className="btn btn-sm" aria-expanded={panel === "ignore"} onClick={() => toggle("ignore")}>
              Ignore…
            </button>
          </>
        )}
        {!security && !closed && (
          <button type="button" className="btn btn-sm" aria-expanded={panel === "request"} onClick={() => toggle("request")}>
            Ask to ignore…
          </button>
        )}
        {security && (closed || state === undefined) && (
          <button
            type="button"
            className="btn btn-sm"
            disabled={act.pending}
            onClick={() => send({ action: "reopen", note: "" })}
            title="Return snoozed or ignored issues to new"
          >
            Reopen
          </button>
        )}
      </div>
      {panel === "assign" && (
        <AssignPanel myId={me?.user?.id} pending={act.pending} onCancel={() => setPanel(null)} onSubmit={(u, t) => send({ action: "assign", user_id: u, team_id: t })} />
      )}
      {panel === "comment" && (
        <NotePanel
          title="Add a comment"
          submit="Add comment"
          pending={act.pending}
          onCancel={() => setPanel(null)}
          onSubmit={(note) => send({ action: "comment", note })}
        />
      )}
      {panel === "suppress" && (
        <SnoozePanel
          pending={act.pending}
          onCancel={() => setPanel(null)}
          onSubmit={(v) => send({ action: "suppress", note: v.note, mitigation: v.mitigation || undefined, until: v.until, until_fix: v.untilFix || undefined })}
        />
      )}
      {panel === "ignore" && (
        <IgnorePanel
          title="Ignore"
          submit="Ignore"
          explain="Ignored issues are shown as Accepted, with the reason. They come back as new when the expiry passes, or when a fix ships if you choose that."
          pending={act.pending}
          onCancel={() => setPanel(null)}
          onSubmit={(v) => send({ action: "ignore", ...v })}
        />
      )}
      {panel === "request" && (
        <IgnorePanel
          title="Ask to ignore"
          submit="Send request"
          explain="Your role cannot ignore issues. This sends a request to your security team. Nothing changes until someone approves it."
          pending={act.pending}
          onCancel={() => setPanel(null)}
          onSubmit={ask}
        />
      )}
      <ErrorBox error={act.error} title="Action failed" />
      {result && (
        <Notice kind={failures.length ? "warn" : "success"}>
          {result}
          {failures.length > 0 && (
            <>
              {" "}
              {failures.length} could not be changed:
              <ul className="banner-list small">
                {failures.slice(0, 20).map((f, i) => (
                  <li key={i}>{f}</li>
                ))}
                {failures.length > 20 && <li>…and {failures.length - 20} more</li>}
              </ul>
            </>
          )}
        </Notice>
      )}
    </div>
  );
}

const REASON_HELP: Record<IgnoreReason, string> = {
  accepted_risk: "You know the risk and accept it for a while.",
  false_positive: "The issue does not apply here. Its verification is set to rejected.",
  mitigated: "Something else reduces the risk, such as a WAF rule or a disabled feature.",
  no_fix: "No fixed version exists yet.",
};

export interface IgnoreFormValue {
  reason: IgnoreReason;
  scope: IgnoreScope;
  expiry: IgnoreExpiry;
  until?: string;
  note: string;
  mitigation?: string;
}

let panelSeq = 0;

/** Snooze until a date, or until a fixed version exists. */
function SnoozePanel({
  pending,
  onSubmit,
  onCancel,
}: {
  pending: boolean;
  onSubmit: (v: { note: string; mitigation: string; until?: string; untilFix: boolean }) => void;
  onCancel: () => void;
}) {
  const [id] = useState(() => `sp${++panelSeq}`);
  const maxDays = useExceptionMaxDays();
  const [mode, setMode] = useState<"date" | "fix">("date");
  const [note, setNote] = useState("");
  const [mitigation, setMitigation] = useState("");
  const [day, setDay] = useState(isoDate(addDays(Math.min(30, maxDays))));
  const go = (e: FormEvent) => {
    e.preventDefault();
    if (!note.trim()) return;
    onSubmit({ note: note.trim(), mitigation: mitigation.trim(), until: mode === "date" ? untilFromDate(day, maxDays) : undefined, untilFix: mode === "fix" });
  };
  return (
    <form className="action-panel form form-compact" onSubmit={go} aria-label="Snooze">
      <strong>Snooze</strong>
      <p className="hint">Hides the issue for now. It comes back as new on its own.</p>
      <fieldset className="field">
        <legend>Until</legend>
        <ul className="choice-list">
          <li>
            <label className="choice">
              <input type="radio" name={`${id}-mode`} checked={mode === "date"} onChange={() => setMode("date")} />
              <span>A date</span>
            </label>
          </li>
          <li>
            <label className="choice">
              <input type="radio" name={`${id}-mode`} checked={mode === "fix"} onChange={() => setMode("fix")} />
              <span>
                A fix ships
                <span className="hint"> It comes back when a free fixed version exists, or after {maxDays.toLocaleString()} days at most.</span>
              </span>
            </label>
          </li>
        </ul>
      </fieldset>
      {mode === "date" && <DateField id={id} day={day} setDay={setDay} maxDays={maxDays} />}
      <ReasonFields id={id} note={note} setNote={setNote} mitigation={mitigation} setMitigation={setMitigation} />
      <div className="form-actions">
        <button type="submit" className="btn btn-primary btn-sm" disabled={pending || !note.trim() || (mode === "date" && !day)}>
          Snooze
        </button>
        <button type="button" className="btn btn-sm" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

/** Ignore (or ask to ignore) with a reason, a scope and an expiry. */
export function IgnorePanel({
  title,
  submit,
  explain,
  pending,
  onSubmit,
  onCancel,
}: {
  title: string;
  submit: string;
  explain: string;
  pending: boolean;
  onSubmit: (v: IgnoreFormValue) => void;
  onCancel: () => void;
}) {
  const [id] = useState(() => `ip${++panelSeq}`);
  const maxDays = useExceptionMaxDays();
  const [reason, setReason] = useState<IgnoreReason>("accepted_risk");
  const [scope, setScope] = useState<IgnoreScope>("asset");
  const [expiry, setExpiry] = useState<IgnoreExpiry>("date");
  const [note, setNote] = useState("");
  const [mitigation, setMitigation] = useState("");
  const [day, setDay] = useState(isoDate(addDays(Math.min(30, maxDays))));
  useEffect(() => {
    if (expiry === "never" && reason !== "false_positive") setExpiry("date");
  }, [reason, expiry]);
  const go = (e: FormEvent) => {
    e.preventDefault();
    if (!note.trim()) return;
    onSubmit({
      reason,
      scope,
      expiry,
      until: expiry === "date" ? untilFromDate(day, maxDays) : undefined,
      note: note.trim(),
      mitigation: mitigation.trim() || undefined,
    });
  };
  return (
    <form className="action-panel form form-compact" onSubmit={go} aria-label={title}>
      <strong>{title}</strong>
      <p className="hint">{explain}</p>
      <div className="field">
        <label htmlFor={`${id}-reason`}>Why</label>
        <select id={`${id}-reason`} value={reason} onChange={(e) => setReason(e.target.value as IgnoreReason)} aria-describedby={`${id}-reason-hint`}>
          {IGNORE_REASONS.map((r) => (
            <option key={r} value={r}>
              {IGNORE_REASON_LABEL[r]}
            </option>
          ))}
        </select>
        <p className="hint" id={`${id}-reason-hint`}>
          {REASON_HELP[reason]}
        </p>
      </div>
      <fieldset className="field">
        <legend>Where</legend>
        <ul className="choice-list">
          <li>
            <label className="choice">
              <input type="radio" name={`${id}-scope`} checked={scope === "asset"} onChange={() => setScope("asset")} />
              <span>This asset</span>
            </label>
          </li>
          <li>
            <label className="choice">
              <input type="radio" name={`${id}-scope`} checked={scope === "everywhere"} onChange={() => setScope("everywhere")} />
              <span>
                Every asset
                <span className="hint"> The same issue in the same component, including assets and issues found later.</span>
              </span>
            </label>
          </li>
        </ul>
      </fieldset>
      <fieldset className="field">
        <legend>Until</legend>
        <ul className="choice-list">
          <li>
            <label className="choice">
              <input type="radio" name={`${id}-expiry`} checked={expiry === "date"} onChange={() => setExpiry("date")} />
              <span>A date</span>
            </label>
          </li>
          <li>
            <label className="choice">
              <input type="radio" name={`${id}-expiry`} checked={expiry === "until_fix"} onChange={() => setExpiry("until_fix")} />
              <span>
                A fix ships
                <span className="hint"> Or after {maxDays.toLocaleString()} days at most, the limit in the risk policy.</span>
              </span>
            </label>
          </li>
          <li>
            <label className="choice">
              <input
                type="radio"
                name={`${id}-expiry`}
                checked={expiry === "never"}
                disabled={reason !== "false_positive"}
                onChange={() => setExpiry("never")}
              />
              <span>
                Never
                <span className="hint"> Only for false positives. Other reasons need an end, so someone looks again.</span>
              </span>
            </label>
          </li>
        </ul>
      </fieldset>
      {expiry === "date" && <DateField id={id} day={day} setDay={setDay} maxDays={maxDays} />}
      <ReasonFields id={id} note={note} setNote={setNote} mitigation={mitigation} setMitigation={setMitigation} />
      <div className="form-actions">
        <button type="submit" className="btn btn-primary btn-sm" disabled={pending || !note.trim() || (expiry === "date" && !day)}>
          {submit}
        </button>
        <button type="button" className="btn btn-sm" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function DateField({ id, day, setDay, maxDays }: { id: string; day: string; setDay: (d: string) => void; maxDays: number }) {
  return (
    <div className="field">
      <label htmlFor={`${id}-until`}>Ends on</label>
      <input
        id={`${id}-until`}
        type="date"
        required
        min={isoDate(addDays(1))}
        max={isoDate(addDays(maxDays))}
        value={day}
        aria-describedby={`${id}-until-hint`}
        onChange={(e) => setDay(e.target.value)}
      />
      <p className="hint" id={`${id}-until-hint`}>
        At most {maxDays.toLocaleString()} days from today, set in the risk policy.
      </p>
    </div>
  );
}

function ReasonFields({
  id,
  note,
  setNote,
  mitigation,
  setMitigation,
}: {
  id: string;
  note: string;
  setNote: (v: string) => void;
  mitigation: string;
  setMitigation: (v: string) => void;
}) {
  return (
    <>
      <div className="field">
        <label htmlFor={`${id}-note`}>Reason (required)</label>
        <textarea id={`${id}-note`} required maxLength={2000} value={note} onChange={(e) => setNote(e.target.value)} />
      </div>
      <div className="field">
        <label htmlFor={`${id}-mitigation`}>Mitigation (optional)</label>
        <textarea id={`${id}-mitigation`} maxLength={2000} value={mitigation} aria-describedby={`${id}-mitigation-hint`} onChange={(e) => setMitigation(e.target.value)} />
        <p className="hint" id={`${id}-mitigation-hint`}>
          What reduces the risk meanwhile, e.g. a WAF rule or a disabled feature.
        </p>
      </div>
    </>
  );
}



function NotePanel({
  title,
  explain,
  submit,
  withExpiry,
  pending,
  onSubmit,
  onCancel,
}: {
  title: string;
  explain?: string;
  submit: string;
  withExpiry?: boolean;
  pending: boolean;
  onSubmit: (note: string, until?: string, mitigation?: string) => void;
  onCancel: () => void;
}) {
  const [id] = useState(() => `np${++panelSeq}`);
  const [note, setNote] = useState("");
  const [mitigation, setMitigation] = useState("");
  const maxDays = useExceptionMaxDays();
  const [day, setDay] = useState(isoDate(addDays(30)));
  // Keep the default date inside a policy limit shorter than 30 days.
  useEffect(() => {
    const max = isoDate(addDays(maxDays));
    if (day > max) setDay(max);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [maxDays]);
  const go = (e: FormEvent) => {
    e.preventDefault();
    if (!note.trim()) return;
    if (withExpiry) onSubmit(note.trim(), untilFromDate(day, maxDays), mitigation.trim());
    else onSubmit(note.trim());
  };
  return (
    <form className="action-panel form form-compact" onSubmit={go} aria-label={title}>
      <strong>{title}</strong>
      {explain && <p className="hint">{explain}</p>}
      <div className="field">
        <label htmlFor={`${id}-note`}>{withExpiry ? "Reason (required)" : "Comment"}</label>
        <textarea id={`${id}-note`} required maxLength={2000} value={note} onChange={(e) => setNote(e.target.value)} />
      </div>
      {withExpiry && (
        <div className="field">
          <label htmlFor={`${id}-mitigation`}>Mitigation (optional)</label>
          <textarea
            id={`${id}-mitigation`}
            maxLength={2000}
            value={mitigation}
            aria-describedby={`${id}-mitigation-hint`}
            onChange={(e) => setMitigation(e.target.value)}
          />
          <p className="hint" id={`${id}-mitigation-hint`}>
            What reduces the risk meanwhile, e.g. a WAF rule or a disabled feature.
          </p>
        </div>
      )}
      {withExpiry && (
        <div className="field">
          <label htmlFor={`${id}-until`}>Expires on (required)</label>
          <input
            id={`${id}-until`}
            type="date"
            required
            min={isoDate(addDays(1))}
            max={isoDate(addDays(maxDays))}
            value={day}
            aria-describedby={`${id}-until-hint`}
            onChange={(e) => setDay(e.target.value)}
          />
          <p className="hint" id={`${id}-until-hint`}>
            At most {maxDays.toLocaleString()} days from today, set in the risk policy.
          </p>
        </div>
      )}
      <div className="form-actions">
        <button type="submit" className="btn btn-primary btn-sm" disabled={pending || !note.trim() || (withExpiry && !day)}>
          {submit}
        </button>
        <button type="button" className="btn btn-sm" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function AssignPanel({
  myId,
  pending,
  onSubmit,
  onCancel,
}: {
  myId?: number;
  pending: boolean;
  onSubmit: (userId: number | undefined, teamId: number | undefined) => void;
  onCancel: () => void;
}) {
  const [id] = useState(() => `ap${++panelSeq}`);
  const teams = useLoad(() => api.get<List<Team>>("/teams"), []);
  // Active users (engineer+ may list them for assignment).
  const users = useLoad(() => api.get<List<DirectoryUser>>("/users/directory"), []);
  const [user, setUser] = useState("keep");
  const [team, setTeam] = useState("keep");
  const go = (e: FormEvent) => {
    e.preventDefault();
    const u = user === "keep" ? undefined : Number(user);
    const t = team === "keep" ? undefined : Number(team);
    if (u === undefined && t === undefined) return;
    onSubmit(u, t);
  };
  return (
    <form className="action-panel form form-compact" onSubmit={go} aria-label="Assign">
      <strong>Assign</strong>
      <ErrorBox error={teams.error ?? users.error} />
      <div className="form-grid">
        <div className="field">
          <label htmlFor={`${id}-user`}>Person</label>
          <select id={`${id}-user`} value={user} onChange={(e) => setUser(e.target.value)}>
            <option value="keep">Leave unchanged</option>
            {myId && <option value={String(myId)}>Me</option>}
            <option value="0">Unassigned</option>
            {users.data?.items
              .filter((u) => u.id !== myId)
              .map((u) => (
                <option key={u.id} value={String(u.id)}>
                  {u.name ? `${u.name} <${u.email}>` : u.email}
                </option>
              ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor={`${id}-team`}>Team</label>
          <select id={`${id}-team`} value={team} onChange={(e) => setTeam(e.target.value)}>
            <option value="keep">Leave unchanged</option>
            <option value="0">No team</option>
            {teams.data?.items.map((t) => (
              <option key={t.id} value={String(t.id)}>
                {t.name}
              </option>
            ))}
          </select>
        </div>
      </div>
      <div className="form-actions">
        <button type="submit" className="btn btn-primary btn-sm" disabled={pending || (user === "keep" && team === "keep")}>
          Assign
        </button>
        <button type="button" className="btn btn-sm" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}
