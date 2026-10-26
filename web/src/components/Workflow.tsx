import { useEffect, useState, type FormEvent } from "react";
import { api, type ActionResult, type DirectoryUser, type Finding, type FindingActionName, type FindingActionRequest, type List, type Team } from "../api";
import { useAuth } from "../auth";
import { useAction, useExceptionMaxDays, useLoad } from "../hooks";
import { absTime, relTime } from "../format";
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

type Panel = null | "assign" | "comment" | "suppress" | "accept_risk";

const LABELS: Record<FindingActionName, string> = {
  acknowledge: "Acknowledged",
  start: "Marked in progress",
  reset: "Reset to new",
  assign: "Assigned",
  comment: "Comment added",
  suppress: "Snoozed",
  accept_risk: "Risk accepted",
  reopen: "Reopened",
};

/**
 * Workflow buttons for one finding, a selection, or every open finding of an
 * incident. Engineer: acknowledge/start/reset/assign/comment. Security+:
 * suppress, accept risk (reason + expiry required, mitigation optional) and reopen.
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
  initialPanel?: "assign" | "suppress" | "accept_risk";
  /** Current state for a single finding, to hide actions that cannot apply. */
  state?: string;
  onDone: () => void;
  compact?: boolean;
}) {
  const { can, me } = useAuth();
  const engineer = can("engineer");
  const security = can("security");
  const act = useAction();
  const [panel, setPanel] = useState<Panel>(initialPanel ?? null);
  const [result, setResult] = useState<string | null>(null);
  const [failures, setFailures] = useState<string[]>([]);

  if (!engineer) return null;

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

  const toggle = (p: Panel) => {
    act.clear();
    setPanel(panel === p ? null : p);
  };

  return (
    <div className="workflow-actions">
      <div className="btn-group" role="group" aria-label={count !== null ? `Actions for ${count} ${target.type === "group" ? "issues in this fix" : "selected findings"}` : "Finding actions"}>
        {!closed && (
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
        <button type="button" className="btn btn-sm" aria-expanded={panel === "assign"} onClick={() => toggle("assign")}>
          Assign…
        </button>
        {!compact && (
          <button type="button" className="btn btn-sm" aria-expanded={panel === "comment"} onClick={() => toggle("comment")}>
            Comment…
          </button>
        )}
        {security && !closed && (
          <>
            <button type="button" className="btn btn-sm" aria-expanded={panel === "suppress"} onClick={() => toggle("suppress")}>
              Snooze…
            </button>
            <button type="button" className="btn btn-sm" aria-expanded={panel === "accept_risk"} onClick={() => toggle("accept_risk")}>
              Accept risk…
            </button>
          </>
        )}
        {security && (closed || state === undefined) && (
          <button
            type="button"
            className="btn btn-sm"
            disabled={act.pending}
            onClick={() => send({ action: "reopen", note: "" })}
            title="Return snoozed or risk-accepted issues to new"
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
      {(panel === "suppress" || panel === "accept_risk") && (
        <NotePanel
          title={panel === "suppress" ? "Snooze" : "Accept risk"}
          explain={
            panel === "suppress"
              ? "Hides the issue until the date you pick (stored as suppressed), e.g. a false positive or a compensating control. It comes back as new when the date passes."
              : "Records that the risk is knowingly accepted until the expiry date. It comes back as new when the date passes."
          }
          submit={panel === "suppress" ? "Snooze" : "Accept risk"}
          withExpiry
          pending={act.pending}
          onCancel={() => setPanel(null)}
          onSubmit={(note, until, mitigation) => send({ action: panel, note, until, mitigation: mitigation || undefined })}
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

let panelSeq = 0;

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
