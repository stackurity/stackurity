import { Link } from "react-router";
import type { ReportTrial } from "../api";
import { useAuth } from "../auth";

/**
 * The watermark on a report shortened in trial mode (docs/asset-limits.md).
 * Shown on screen and when printed, so a printed or saved page carries it.
 */
export function TrialBanner({ trial }: { trial: ReportTrial | undefined | null }) {
  const { can, meta } = useAuth();
  if (!trial) return null;
  return (
    <div className="alert alert-warn trial-watermark" role="status">
      <strong>{trial.watermark}</strong>
      <span className="block small">
        During the trial each list in this report shows its first {trial.rows_per_list} rows; the totals are complete.
        {meta?.billing && can("admin") && (
          <>
            {" "}
            <Link to="/settings/billing" className="no-print">
              Choose a plan
            </Link>{" "}
            for complete reports.
          </>
        )}
      </span>
    </div>
  );
}

/** "Trial: 5 more not shown" under a shortened list; nothing when complete. */
export function TrialMore({ trial, list }: { trial: ReportTrial | undefined | null; list: string }) {
  const n = trial?.omitted?.[list] ?? 0;
  if (n <= 0) return null;
  return <p className="small muted trial-more">Trial: {n.toLocaleString()} more not shown.</p>;
}
