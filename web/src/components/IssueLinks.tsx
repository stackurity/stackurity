import type { IssueRef } from "../api";

const TRACKER_LABEL: Record<string, string> = { jira: "Jira", pagerduty: "PagerDuty", servicenow: "ServiceNow" };

/** Links to the tracker records (Jira, PagerDuty, ServiceNow) that follow an incident. */
export function IssueLinks({ issues, compact = false }: { issues: IssueRef[] | null | undefined; compact?: boolean }) {
  if (!issues || issues.length === 0) return compact ? null : <span className="muted">none</span>;
  return (
    <span className={compact ? "small" : undefined}>
      {issues.map((i, n) => (
        <span key={`${i.tracker}-${i.key}`}>
          {n > 0 && ", "}
          {safeHref(i.url) ? (
            <a href={i.url} target="_blank" rel="noopener noreferrer" onClick={(e) => e.stopPropagation()}>
              {TRACKER_LABEL[i.tracker] ?? i.tracker} {i.key}
            </a>
          ) : (
            `${TRACKER_LABEL[i.tracker] ?? i.tracker} ${i.key}`
          )}
          {i.state && (
            <span className="muted" title="Closed in the tracker. Stackurity stops updating it; the findings stay open until a scan shows them fixed.">
              {" "}
              ({i.state} in {TRACKER_LABEL[i.tracker] ?? i.tracker})
            </span>
          )}
        </span>
      ))}
    </span>
  );
}

function safeHref(u: string): boolean {
  return /^https?:\/\//i.test(u);
}
