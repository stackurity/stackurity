import { useState } from "react";
import { Link } from "react-router";
import { api, ApiError } from "../api";
import {
  activityLink,
  proposalActions,
  proposalBadge,
  proposalStatusLine,
  proposalTargets,
  proposalTitle,
  UNREQUESTED_NOTE,
  type AskProposal,
} from "../askProposal";
import { Badge } from "./Badge";

/**
 * A change Ask Stackurity proposed, under its answer: what will change, on
 * what, and Apply / Dismiss. Ask never applies anything; Apply is the
 * person's own request (POST …/proposals/{id}/apply), checked like any
 * other change they make. The card keeps its state with the conversation:
 * proposed, applied, dismissed, expired, failed or undone.
 */
export function AskProposalCard({
  conv,
  proposal,
  onChange,
  onNavigate,
}: {
  conv: number;
  proposal: AskProposal;
  onChange?: (p: AskProposal) => void;
  onNavigate?: () => void;
}) {
  // The latest state from this card's own requests; the panel keeps it too
  // (onChange), so it survives the card being drawn again.
  const [local, setLocal] = useState<AskProposal | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const shown = local && local.id === proposal.id ? local : proposal;
  const p = shown;
  const update = (next: AskProposal) => {
    setLocal(next);
    onChange?.(next);
  };
  const act = async (action: "apply" | "dismiss" | "undo") => {
    setBusy(true);
    setError("");
    try {
      const r = await api.post<{ proposal: AskProposal }>(`/ask/conversations/${conv}/proposals/${p.id}/${action}`, {});
      update(r.proposal);
    } catch (e) {
      const data = e instanceof ApiError ? (e.data as { proposal?: AskProposal } | undefined) : undefined;
      if (data?.proposal) update(data.proposal);
      // A changed preview, a failure or a closed proposal explains itself in
      // the card's status line; anything else is said here.
      if (!data?.proposal) setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const badge = proposalBadge(shown.status);
  const acts = proposalActions(shown);
  const targets = proposalTargets(shown);
  const line = proposalStatusLine(shown);
  return (
    <section className={`ask-proposal ask-proposal-${shown.status}`} aria-label={`Proposed change: ${proposalTitle(shown)}`}>
      <div className="ask-proposal-head">
        <span className="ask-proposal-label">Proposed change</span>
        <Badge status={shown.status} tone={badge.tone} label={badge.label} />
      </div>
      {shown.unrequested && <p className="ask-proposal-unasked small">{UNREQUESTED_NOTE}</p>}
      <p className="ask-proposal-summary">{shown.summary}</p>
      {targets.items.length > 0 && (
        <ul className="ask-proposal-targets small">
          {targets.items.map((t, i) => (
            <li key={i}>
              {t.to ? (
                <Link to={t.to} onClick={onNavigate}>
                  {t.label}
                </Link>
              ) : (
                t.label
              )}
            </li>
          ))}
          {targets.more > 0 && <li className="muted">and {targets.more} more</li>}
        </ul>
      )}
      {shown.notes.length > 0 && (
        <ul className="ask-proposal-notes small muted">
          {shown.notes.map((n, i) => (
            <li key={i}>{n}</li>
          ))}
        </ul>
      )}
      <p className="ask-proposal-status small" role="status">
        {line}
        {shown.status === "applied" && (
          <>
            {" "}
            {shown.link && (
              <Link to={shown.link} onClick={onNavigate}>
                View what changed
              </Link>
            )}
            {shown.link && " · "}
            <Link to={activityLink(shown)} onClick={onNavigate}>
              Activity log
            </Link>
          </>
        )}
      </p>
      {error && (
        <p className="ask-proposal-error small" role="alert">
          {error}
        </p>
      )}
      {(acts.apply || acts.dismiss || acts.undo) && (
        <div className="ask-proposal-actions">
          {acts.apply && (
            <button type="button" className="btn btn-sm btn-primary" disabled={busy} onClick={() => void act("apply")}>
              {busy ? "Applying…" : "Apply"}
            </button>
          )}
          {acts.dismiss && (
            <button type="button" className="btn btn-sm" disabled={busy} onClick={() => void act("dismiss")}>
              Dismiss
            </button>
          )}
          {acts.undo && (
            <button type="button" className="btn btn-sm" disabled={busy} onClick={() => void act("undo")} title="Reverse this change">
              Undo
            </button>
          )}
        </div>
      )}
    </section>
  );
}
