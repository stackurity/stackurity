import { Link } from "react-router";
import type { FixGroup } from "../api";
import {
  fixLink,
  milestoneText,
  milestoneTiles,
  phaseText,
  progressRows,
  type FirstCheckNumbers,
  type FirstCheckPhase,
  type Source,
} from "../firstCheck";
import { StatTile } from "./ui";
import { PlaceText } from "./PlaceText";

/*
 * The first check on Get started: progress with the numbers as they arrive,
 * then the milestone. The words and numbers are in firstCheck.ts; these only
 * lay them out.
 */

export function FirstCheckProgress({
  x,
  phase,
  source,
  what,
  overdue,
}: {
  x: FirstCheckNumbers;
  phase: FirstCheckPhase;
  /** What was sent, when known: names the first line. */
  source?: Source;
  what: string;
  overdue?: boolean;
}) {
  const t = phaseText(phase, x, source, what, overdue);
  return (
    <div className="first-check" data-phase={phase}>
      <ol className="first-check-rows" aria-label="Progress of the first check">
        {progressRows(x, phase, source).map((r) => (
          <li key={r.key} className={`first-check-row first-check-${r.state}`}>
            {r.state === "done" ? (
              <span className="onboard-check" aria-hidden="true">
                ✓
              </span>
            ) : r.state === "active" ? (
              <span className="onboard-spinner" aria-hidden="true" />
            ) : (
              <span className="first-check-todo" aria-hidden="true" />
            )}
            <span className="first-check-label">{r.label}</span>
            <span className="first-check-value">{r.value}</span>
            <span className="sr-only">{r.state === "done" ? " (done)" : r.state === "active" ? " (in progress)" : " (not yet)"}</span>
          </li>
        ))}
      </ol>
      <div role="status" aria-live="polite">
        <p className="onboard-big">{t.title}</p>
        {t.text && (
          <p className="muted">
            <PlaceText text={t.text} />
          </p>
        )}
      </div>
    </div>
  );
}

export function FirstCheckDone({ x, top, projectId }: { x: FirstCheckNumbers; top: FixGroup | null; projectId: number }) {
  const q = `project=${projectId}`;
  return (
    <div className="first-check-done">
      <h2 className="onboard-headline">
        <span className="onboard-check" aria-hidden="true">
          ✓
        </span>{" "}
        Your first check is done
      </h2>
      <div className="tiles first-check-tiles">
        {milestoneTiles(x).map((t) => (
          <StatTile key={t.key} label={t.label} value={t.value} />
        ))}
      </div>
      <p>{milestoneText(x)}</p>
      {top && (
        <div className="first-check-top">
          <p className="tile-label">Top recommended fix</p>
          <p className="onboard-big">
            <Link to={`${fixLink(top)}?${q}`}>{top.title}</Link>
          </p>
          <p className="small muted">
            {top.asset_name} · fixes {top.unique_issues ?? top.finding_count} {(top.unique_issues ?? top.finding_count) === 1 ? "issue" : "issues"}
            {top.sos ? " · SOS" : ""}
            {top.top_priority ? ` · ${top.top_priority}` : ""}
          </p>
        </div>
      )}
      <p className="onboard-links">
        {top && (
          <Link className="btn btn-primary" to={`${fixLink(top)}?${q}`}>
            Open the top fix
          </Link>
        )}
        {x.issues > 0 && (
          <Link className="btn" to={`/fixes?${q}`}>
            See every fix
          </Link>
        )}
        <Link className="btn" to={`/coverage?${q}`}>
          See the coverage
        </Link>
      </p>
    </div>
  );
}
