import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router";
import { api, type GateException, type GateExceptionList, type GateExceptionRequest, type GateViolation } from "../api";
import { gateExceptionsEmpty } from "../emptyCopy";
import { absTime } from "../format";
import { useAction, useExceptionMaxDays, useLoad } from "../hooks";
import {
  dayFromNow,
  EXCEPTION_REASONS,
  exceptionDraftToRequest,
  exceptionReasonLabel,
  exceptionStatus,
  exceptionTargetText,
  isActiveException,
  newExceptionDraft,
  type ExceptionDraft,
  type ExceptionSubject,
} from "../policyGates";
import { Badge } from "./Badge";
import { CardSkeleton } from "./Skeleton";
import { ChoiceCards, EmptyState, ErrorBox, Notice, Pager, RelativeTime } from "./ui";

/*
 * Exceptions to policy gates (docs/policy-gates.md, Exceptions): asked for
 * from a violation row (pages/PolicyViolations.tsx) or a policy on an
 * asset's Policy gates card (PolicyGates.tsx), decided on Approvals →
 * Policy exceptions. One approver decides, as for ignore requests.
 */

export function ExceptionStatusBadge({ x }: { x: GateException }) {
  const s = exceptionStatus(x);
  return <Badge status={x.status} tone={s.tone} label={s.label} />;
}

/** "until 3 Dec 2026, 23:59" for an exception in force; "" otherwise. */
export function untilText(x: Pick<GateException, "status" | "expires_at">): string {
  return isActiveException(x) && x.expires_at ? `until ${absTime(x.expires_at)}` : "";
}

/**
 * The form for asking. subject: the policy and asset, and the violation's
 * finding or leaked key when asked from a violation (it can then cover
 * this issue only, or every violation of the policy on the asset).
 */
export function ExceptionRequestForm({
  subject,
  policyName,
  assetName,
  issue,
  maxDays,
  pending = false,
  onSubmit,
  onCancel,
  idPrefix = "gx",
}: {
  subject: ExceptionSubject;
  policyName: string;
  assetName: string;
  /** The violation's issue, in words ("CVE-2026-1 in openssl 3.0.2"); absent for a whole-asset request. */
  issue?: string;
  maxDays: number;
  pending?: boolean;
  onSubmit: (req: GateExceptionRequest) => void;
  onCancel: () => void;
  idPrefix?: string;
}) {
  const [d, setD] = useState<ExceptionDraft>(() => newExceptionDraft(subject, maxDays));
  const [problem, setProblem] = useState("");
  const set = (patch: Partial<ExceptionDraft>) => setD((x) => ({ ...x, ...patch }));
  const id = (s: string) => `${idPrefix}-${s}`;
  const hasIssue = subject.finding_id != null || subject.leak_id != null;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const out = exceptionDraftToRequest(d, subject, maxDays);
    setProblem(out.error ?? "");
    if (out.request) onSubmit(out.request);
  };
  return (
    <form className="form form-compact exception-form" onSubmit={submit} aria-label={`Ask for an exception to ${policyName}`}>
      <p className="small">
        Ask for <strong>{policyName}</strong> not to count against <strong>{assetName}</strong> until a date. A security or admin user of the asset
        approves or declines it on Approvals. While it is in force, CI and deploy checks leave out what it covers; when it ends, the violation counts
        again.
      </p>
      {hasIssue && (
        <ChoiceCards
          name={id("target")}
          legend="What it covers"
          value={d.target}
          onChange={(target) => set({ target })}
          columns={2}
          options={[
            { value: "finding", label: "This issue only", description: issue ? `${issue}. Other violations on the asset still count.` : "Other violations on the asset still count." },
            { value: "asset", label: "Every violation of this policy on this asset", description: "Including ones found later, until the end date." },
          ]}
        />
      )}
      <ChoiceCards name={id("reason")} legend="Reason" value={d.reason} onChange={(reason) => set({ reason })} columns={2} options={EXCEPTION_REASONS} />
      <div className="field">
        <label htmlFor={id("note")}>Why</label>
        <textarea id={id("note")} rows={2} maxLength={4000} value={d.note} onChange={(e) => set({ note: e.target.value })} />
        <p className="hint">The approver and the audit log see this. Say what keeps the risk down, or when it will be fixed.</p>
      </div>
      <div className="field">
        <label htmlFor={id("until")}>Ends on</label>
        <input id={id("until")} type="date" required min={dayFromNow(1)} max={dayFromNow(maxDays)} value={d.day} onChange={(e) => set({ day: e.target.value })} />
        <p className="hint">At most {maxDays === 1 ? "1 day" : `${maxDays} days`} from today, the limit set in the risk policy. The approver can shorten it.</p>
      </div>
      {problem && (
        <p className="hint hint-error" role="alert">
          {problem}
        </p>
      )}
      <div className="row-actions">
        <button type="submit" className="btn btn-primary btn-sm" disabled={pending}>
          Ask for an exception
        </button>
        <button type="button" className="btn btn-sm" disabled={pending} onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

/** One ask: what it is about, and the words the form shows. */
export interface ExceptionAsk {
  /** Unique on the page, for the form's ids. */
  key: string;
  subject: ExceptionSubject;
  policyName: string;
  assetName: string;
  /** The violation's issue in words; absent for a whole-asset ask. */
  issue?: string;
}

/** The control on a violation or policy line: Ask for an exception, or the request already waiting. */
export function ExceptionAskButton({ waiting, onAsk, disabled = false }: { waiting?: GateException; onAsk: () => void; disabled?: boolean }) {
  if (waiting) {
    return (
      <span className="small muted">
        Exception <Link to="/approvals?tab=policy">#{waiting.id}</Link> is waiting for a decision.
      </span>
    );
  }
  return (
    <button type="button" className="btn btn-sm" disabled={disabled} onClick={onAsk}>
      Ask for an exception
    </button>
  );
}

/** Said next to the list once someone has asked. */
export function ExceptionAskedNotice({ x }: { x: GateException }) {
  return (
    <Notice kind="success">
      Exception #{x.id} asked for: {exceptionTargetText(x)}. It waits on <Link to="/approvals?tab=policy">Approvals → Policy exceptions</Link> for a security
      or admin user of the asset.
    </Notice>
  );
}

/**
 * The form for one ask, full width above the list it came from, with what
 * went wrong under it. onAsked gets the new request.
 */
export function ExceptionAskPanel({ ask, onCancel, onAsked }: { ask: ExceptionAsk; onCancel: () => void; onAsked: (x: GateException) => void }) {
  const act = useAction();
  const maxDays = useExceptionMaxDays();
  // The form opens above the list, which may be scrolled past: bring it into view.
  const ref = useRef<HTMLElement>(null);
  useEffect(() => {
    ref.current?.scrollIntoView?.({ block: "nearest" });
  }, [ask.key]);
  return (
    <section ref={ref} className="exception-ask" aria-label="Ask for an exception">
      <ExceptionRequestForm
        key={`${ask.key}-${maxDays}`}
        subject={ask.subject}
        policyName={ask.policyName}
        assetName={ask.assetName}
        issue={ask.issue}
        maxDays={maxDays}
        pending={act.pending}
        idPrefix={`gx-${ask.key}`}
        onCancel={onCancel}
        onSubmit={async (req) => {
          const x = await act.run(() => api.post<GateException>("/gate-policies/exceptions", req));
          if (x) onAsked(x);
        }}
      />
      <ErrorBox error={act.error} title="Could not ask for the exception" />
    </section>
  );
}

/** What was asked and decided, in a few lines. */
export function ExceptionBody({ x }: { x: GateException }) {
  return (
    <>
      <p className="small">
        <strong>{exceptionReasonLabel(x.reason)}</strong> · {exceptionTargetText(x)} ·{" "}
        {isActiveException(x) && x.expires_at
          ? `until ${absTime(x.expires_at)}`
          : x.status === "pending" && x.requested_expires_at
            ? `asked until ${absTime(x.requested_expires_at)}`
            : x.status === "pending"
              ? "end date left to the approver"
              : x.expires_at
                ? `was until ${absTime(x.expires_at)}`
                : "no end date"}
      </p>
      <p className="small">
        <span className="muted">Why:</span> {x.note}
      </p>
      <p className="small muted">
        Asked by {x.requested_by || "someone"} <RelativeTime iso={x.requested_at} />
        {x.decided_at && (
          <>
            {" "}
            · {x.status === "declined" ? "declined" : "approved"} by {x.decided_by || "someone"} <RelativeTime iso={x.decided_at} />
          </>
        )}
        {x.ended_at && x.end_reason !== "expired" && (
          <>
            {" "}
            · ended <RelativeTime iso={x.ended_at} />
            {x.ended_by ? ` by ${x.ended_by}` : ""}
          </>
        )}
      </p>
      {x.decision_note && (
        <p className="small">
          <span className="muted">Decision note:</span> {x.decision_note}
        </p>
      )}
      {x.end_note && (
        <p className="small">
          <span className="muted">Why it ended:</span> {x.end_note}
        </p>
      )}
    </>
  );
}

function Decide({ x, maxDays, onDone }: { x: GateException; maxDays: number; onDone: (msg: string) => void }) {
  const act = useAction();
  const [note, setNote] = useState("");
  const [day, setDay] = useState("");
  const [problem, setProblem] = useState("");
  const id = `gxd-${x.id}`;
  const decide = async (decision: "approve" | "decline") => {
    if (decision === "decline" && !note.trim()) {
      setProblem("Say why it is declined: the person who asked sees it.");
      return;
    }
    setProblem("");
    const body: Record<string, string> = { decision, note: note.trim() };
    if (decision === "approve" && day) body.expires_at = new Date(`${day}T23:59:59`).toISOString();
    const out = await act.run(() => api.post<GateException>(`/gate-policies/exceptions/${x.id}/decision`, body));
    if (out) onDone(decision === "approve" ? `Exception #${x.id} approved ${untilText(out)}.` : `Exception #${x.id} declined.`);
  };
  return (
    <>
      <div className="approval-actions form form-compact">
        <div className="field">
          <label htmlFor={`${id}-note`}>Note (needed to decline)</label>
          <input id={`${id}-note`} maxLength={4000} value={note} onChange={(e) => setNote(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor={`${id}-until`}>Ends on (optional)</label>
          <input id={`${id}-until`} type="date" min={dayFromNow(1)} max={dayFromNow(maxDays)} value={day} onChange={(e) => setDay(e.target.value)} />
        </div>
        <button type="button" className="btn btn-sm btn-primary" disabled={act.pending} onClick={() => decide("approve")}>
          Approve
        </button>
        <button type="button" className="btn btn-sm" disabled={act.pending} onClick={() => decide("decline")}>
          Decline
        </button>
      </div>
      <p className="hint">Left empty, it ends on the date asked for, or after the risk policy&apos;s limit of {maxDays} days.</p>
      {problem && (
        <p className="hint hint-error" role="alert">
          {problem}
        </p>
      )}
      <ErrorBox error={act.error} title="Could not decide" />
    </>
  );
}

function EndEarly({ x, onDone }: { x: GateException; onDone: (msg: string) => void }) {
  const act = useAction();
  const [open, setOpen] = useState(false);
  const [note, setNote] = useState("");
  const id = `gxe-${x.id}`;
  if (!open) {
    return (
      <div className="approval-actions">
        <button type="button" className="btn btn-sm btn-link-danger" onClick={() => setOpen(true)}>
          End early
        </button>
      </div>
    );
  }
  const end = async () => {
    const out = await act.run(() => api.post<GateException>(`/gate-policies/exceptions/${x.id}/end`, { note: note.trim() }));
    if (out) onDone(`Exception #${x.id} ended: its violations count again.`);
  };
  return (
    <>
      <div className="approval-actions form form-compact">
        <div className="field">
          <label htmlFor={id}>Why (optional)</label>
          <input id={id} maxLength={4000} value={note} onChange={(e) => setNote(e.target.value)} />
        </div>
        <button type="button" className="btn btn-sm" disabled={act.pending} onClick={end}>
          End the exception
        </button>
        <button type="button" className="btn btn-sm btn-link" disabled={act.pending} onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
      <ErrorBox error={act.error} title="Could not end the exception" />
    </>
  );
}

/** The list on Approvals → Policy exceptions, from the server's answer: rendered by tests as is. */
export function ExceptionItems({
  items,
  canDecide,
  maxDays,
  onDone,
}: {
  items: GateException[];
  canDecide: boolean;
  maxDays: number;
  onDone: (msg: string) => void;
}) {
  return (
    <ul className="approval-list" aria-label="Policy exceptions">
      {items.map((x) => (
        <li key={x.id} className="approval">
          <h3 className="badges">
            <ExceptionStatusBadge x={x} />
            <span className="break">
              <Link to={`/fixes/policy-violations?policy_id=${x.policy_id}`}>{x.policy_name || `Policy #${x.policy_id}`}</Link> on{" "}
              <Link to={`/assets/${x.asset_id}`}>{x.asset_name || `asset #${x.asset_id}`}</Link>
            </span>
          </h3>
          <ExceptionBody x={x} />
          {canDecide && x.status === "pending" && <Decide x={x} maxDays={maxDays} onDone={onDone} />}
          {canDecide && isActiveException(x) && <EndEarly x={x} onDone={onDone} />}
        </li>
      ))}
    </ul>
  );
}

/** Approvals → Policy exceptions: waiting ones first, or every one. */
export function PolicyExceptionsTab() {
  const [status, setStatus] = useState<"pending" | "all">("pending");
  const [offset, setOffset] = useState(0);
  const [done, setDone] = useState<string | null>(null);
  const maxDays = useExceptionMaxDays();
  const res = useLoad(() => api.get<GateExceptionList>("/gate-policies/exceptions", { status, limit: 50, offset }), [status, offset]);
  return (
    <>
      <p className="hint">
        Requests for a policy gate not to count against an asset, or one issue on it, until a date. A security or admin user of the asset decides;
        while an exception is in force, CI and deploy checks leave out what it covers.
      </p>
      <label className="check">
        <input
          type="checkbox"
          checked={status === "all"}
          onChange={(e) => {
            setStatus(e.target.checked ? "all" : "pending");
            setOffset(0);
          }}
        />{" "}
        Show decided and ended exceptions too
      </label>
      {done && <Notice kind="success">{done}</Notice>}
      <ErrorBox error={res.error} title="Could not load the policy exceptions" />
      {!res.data && !res.error && <CardSkeleton label="Loading policy exceptions…" />}
      {res.data && res.data.items.length === 0 && <EmptyState {...gateExceptionsEmpty(status, res.data.can_decide)} help="approvals" />}
      {res.data && res.data.items.length > 0 && (
        <ExceptionItems
          items={res.data.items}
          canDecide={res.data.can_decide}
          maxDays={maxDays}
          onDone={(msg) => {
            setDone(msg);
            res.reload();
          }}
        />
      )}
      {res.data && <Pager total={res.data.total} limit={50} offset={offset} onChange={setOffset} />}
    </>
  );
}

/** Exceptions in force, for the Violations page: what is left out of the list, and until when. */
export function ExceptionsInForce({ items }: { items: GateException[] }) {
  if (items.length === 0) return null;
  return (
    <details className="exceptions-in-force">
      <summary>
        {items.length === 1 ? "1 exception is" : `${items.length} exceptions are`} in force: what they cover is not counted as a violation until they end
      </summary>
      <ul className="approval-list" aria-label="Exceptions in force">
        {items.map((x) => (
          <li key={x.id} className="approval">
            <p className="small">
              <strong>{x.policy_name}</strong> · {exceptionTargetText(x)} · {untilText(x)} · {exceptionReasonLabel(x.reason)}
            </p>
            <p className="small muted">
              Approved by {x.decided_by || "someone"} · <Link to="/approvals?tab=policy">Exception #{x.id}</Link>
            </p>
          </li>
        ))}
      </ul>
    </details>
  );
}

/** The issue of a violation, in words, for the form: "CVE-2026-1 in openssl 3.0.2". */
export function violationIssue(v: GateViolation): string {
  return v.component ? `${v.key} in ${v.component}` : v.key;
}

/** An ask from a violation row: this issue, or every violation of the policy on the asset. */
export function violationAsk(v: GateViolation): ExceptionAsk {
  return {
    key: `${v.policy_id}-${v.violation_key.replace(/\W/g, "-")}-${v.asset_id}`,
    subject: { policy_id: v.policy_id, asset_id: v.asset_id, finding_id: v.finding_id, leak_id: v.leak_id },
    policyName: v.policy_name,
    assetName: v.asset_name,
    issue: violationIssue(v),
  };
}
