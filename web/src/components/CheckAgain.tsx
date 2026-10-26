import { useEffect, type ReactNode } from "react";
import { Link } from "react-router";
import { api, type Asset, type Check, type List } from "../api";
import { useAuth } from "../auth";
import { useAction, useLoad } from "../hooks";
import { absTime, plural } from "../format";
import { Badge, type Tone } from "./Badge";
import { Code, CodeBlock, ErrorBox, RelativeTime } from "./ui";

/** How recently an agent must have asked for us to call it a 0.7 agent that polls. */
const POLL_FRESH_MS = 15 * 60 * 1000;

export const OUTCOME: Record<string, { label: string; tone: Tone }> = {
  passed: { label: "Passed", tone: "good" },
  partly_fixed: { label: "Partly fixed", tone: "warn" },
  still_open: { label: "Still open", tone: "bad" },
  expired: { label: "No report", tone: "muted" },
};

/** A check's state as one chip: its outcome, or waiting / checking. */
export function CheckBadge({ c }: { c: Check }) {
  if (c.status === "done") {
    const o = OUTCOME[c.outcome] ?? { label: c.outcome, tone: "info" as Tone };
    return <Badge status={`check-${c.outcome}`} tone={o.tone} label={o.label} />;
  }
  if (c.status === "evaluating") return <Badge status="check-evaluating" tone="info" label="Checking the report" />;
  return <Badge status="check-waiting" tone="warn" label="Waiting for a report" />;
}

/** Whether the asset's agent asks for check-again requests (0.7 or newer). */
export function agentPolls(polledAt: string | null | undefined): boolean {
  return Boolean(polledAt) && Date.now() - new Date(polledAt!).getTime() < POLL_FRESH_MS;
}

function scanCommand(asset?: Asset | null): string {
  const url = asset?.attributes?.git_url || "$CI_REPOSITORY_URL";
  return `stackurity scan . --git-url "${url}"`;
}

/** What a check that has no result yet is waiting for. */
function Waiting({ c, asset }: { c: Check; asset?: Asset | null }) {
  if (c.status === "evaluating")
    return <p className="small">{c.picked_up_at ? "The agent has reported." : "A report arrived."} Stackurity is checking it now.</p>;
  if (c.method === "agent") {
    if (agentPolls(c.agent_polled_at ?? asset?.agent_polled_at))
      return <p className="small">Waiting for the agent to report (it asks every minute).</p>;
    return (
      <>
        <p className="small">Waiting for the agent. Agents older than 0.7 report on their interval; restart the agent to report now.</p>
        <CodeBlock label="Report now" text="sudo systemctl restart stackurity-agent" />
      </>
    );
  }
  if (c.method === "integration") return <p className="small">The server is scanning the repository again. This takes a minute or two.</p>;
  if (c.asset_kind === "repository" || asset?.kind === "repository")
    return (
      <>
        <p className="small">
          Waiting for the next scan. Scan the repository again in CI or on your machine, with a collector token in <Code>STACKURITY_TOKEN</Code>:
        </p>
        <CodeBlock label="Scan now" text={scanCommand(asset)} />
      </>
    );
  return <p className="small">Waiting for the next report of this asset.</p>;
}

/** The result of a finished check, in one or two sentences. */
export function CheckResultText({ c, issuesLink }: { c: Check; issuesLink?: string }) {
  const when = c.completed_at ? <time dateTime={c.completed_at}>{absTime(c.completed_at)}</time> : null;
  const whole = !c.fix_group;
  let text: ReactNode;
  switch (c.outcome) {
    case "passed":
      text = whole ? (
        <>
          Passed {when}: every issue open before the check is gone{c.new_issues > 0 ? `, and it found ${plural(c.new_issues, "new issue")}` : ""}.
        </>
      ) : (
        <>Passed {when}: all {plural(c.fixed, "issue")} of this fix are gone.</>
      );
      break;
    case "partly_fixed":
      text = (
        <>
          Partly fixed {when}: {c.fixed.toLocaleString()} fixed,{" "}
          {issuesLink ? <Link to={issuesLink}>{c.remaining.toLocaleString()} left</Link> : `${c.remaining.toLocaleString()} left`}
          {whole && c.new_issues > 0 ? `, ${plural(c.new_issues, "new issue")}` : ""}.
        </>
      );
      break;
    case "still_open":
      text = (
        <>
          Still open {when}: none of the {issuesLink ? <Link to={issuesLink}>{plural(c.remaining, "issue")}</Link> : plural(c.remaining, "issue")} is
          gone{whole && c.new_issues > 0 ? `, and it found ${plural(c.new_issues, "new issue")}` : ""}.
        </>
      );
      break;
    case "expired":
      text = <>No report arrived within 7 days of the request, so nothing was checked.</>;
      break;
    default:
      text = c.outcome;
  }
  return <p className="small">{text}</p>;
}

/**
 * Check again for an asset or one fix on it: the last check and its result,
 * what it waits for, and the buttons to ask again or say a fix was applied.
 * A check that is not done is polled every 10 seconds.
 */
export function CheckAgain({
  asset,
  fixGroup,
  onChanged,
}: {
  asset: Asset | undefined | null;
  /** The fix (fix group id); without it the check covers the whole asset. */
  fixGroup?: string;
  onChanged?: () => void;
}) {
  const { can } = useAuth();
  const act = useAction();
  const scope = fixGroup ? { fix_group: fixGroup } : { asset_id: asset?.id };
  const last = useLoad(
    () => (fixGroup || asset ? api.get<List<Check>>("/checks", { ...scope, limit: 1 }) : Promise.resolve(null)),
    [fixGroup, asset?.id],
  );
  const c = last.data?.items[0];
  const open = c && c.status !== "done";
  useEffect(() => {
    if (!open) return;
    const t = setInterval(last.reload, 10_000);
    return () => clearInterval(t);
  }, [open, last.reload]);
  // When the check finishes, the page's issues have changed too.
  const done = c?.status === "done" ? c.id : 0;
  useEffect(() => {
    if (done) onChanged?.();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [done]);
  if (!asset) return null;

  const issuesLink = fixGroup ? `/fixes/issues?fix_group=${encodeURIComponent(fixGroup)}` : `/fixes/issues?asset_id=${asset.id}`;
  const base = fixGroup ? `/fix-groups/${encodeURIComponent(fixGroup)}` : `/assets/${asset.id}`;
  const check = async () => {
    if (await act.run(() => api.post<Check>(`${base}/check`))) last.reload();
  };
  const applied = async () => {
    if (await act.run(() => api.post(`${base}/applied`))) {
      last.reload();
      onChanged?.();
    }
  };

  return (
    <div className="check-again" aria-live="polite">
      <p className="small">
        <strong>Last checked</strong> <RelativeTime iso={asset.last_seen} />. Issues close on their own when a check no longer finds them.
      </p>
      {c && (
        <div className="check-last">
          <p className="small badges">
            <CheckBadge c={c} />
            <span className="muted">
              {c.reason === "applied" ? "Applied and checked" : "Asked"} by {c.requested_by || "someone"} <RelativeTime iso={c.requested_at} />
            </span>
          </p>
          {c.status === "done" ? <CheckResultText c={c} issuesLink={issuesLink} /> : <Waiting c={c} asset={asset} />}
        </div>
      )}
      {!c && asset.kind === "host" && !agentPolls(asset.agent_polled_at) && (
        <p className="small muted">
          Agents older than 0.7 report every 6 hours and when they start. Restart the agent to report now, or upgrade it so Check again works
          within a minute.
        </p>
      )}
      {!c && asset.kind === "repository" && (
        <>
          <p className="small">Scan the repository again, or press Check again if it is connected through Integrations.</p>
          <CodeBlock label="Scan now" text={scanCommand(asset)} />
        </>
      )}
      {can("engineer") && (
        <div className="form-actions check-actions">
          <button type="button" className="btn btn-sm btn-primary" disabled={act.pending || Boolean(open && c?.status === "waiting")} onClick={check}>
            {open ? "Checking" : "Check again"}
          </button>
          {fixGroup && (
            <button
              type="button"
              className="btn btn-sm"
              disabled={act.pending}
              onClick={applied}
              title="Marks this fix's issues in progress and asks for a check. It never closes an issue by itself."
            >
              I applied this
            </button>
          )}
        </div>
      )}
      {fixGroup && can("engineer") && (
        <p className="hint">
          I applied this marks the issues in progress ("applied, waiting for a check") and asks for a check. Only the fresh report closes them.
        </p>
      )}
      <ErrorBox error={act.error ?? last.error} title="Check again failed" />
    </div>
  );
}
