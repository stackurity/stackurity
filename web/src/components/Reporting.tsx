import { Link } from "react-router";
import type { Asset, OneOffGroup } from "../api";
import { assetNoun, daysSince, everyText, ONE_OFF_AGING_DAYS, oneOffText, reportDate as shortDate } from "../reporting";
import { CodeBlock, Notice } from "./ui";

/** Home: "5 repositories scanned once (as of 26 Oct)", a quiet line. */
export function OneOffLine({ groups }: { groups?: OneOffGroup[] }) {
  const t = oneOffText(groups);
  if (!t) return null;
  return (
    <p className="home-oneoff small">
      {t.text}. {t.age && <>{t.age} </>}
      <Link to="/help/asset-reporting#one-off">Set up a scheduled scan</Link> to keep {t.count === 1 ? "it" : "them"} current.
    </p>
  );
}

function scheduledSnippets(origin: string) {
  const github = `on:
  push:
    branches: [main]
  schedule:
    - cron: "0 6 * * *"   # every day at 06:00 UTC
jobs:
  stackurity:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: stackurity/scan-action@v1
        with:
          server: ${origin}
          token: \${{ secrets.STACKURITY_TOKEN }}`;
  const gitlab = `stackurity:
  image:
    name: ghcr.io/stackurity/stackurity:latest
    entrypoint: [""]
  variables:
    STACKURITY_SERVER: ${origin}
    # STACKURITY_TOKEN: a masked CI/CD variable
  script:
    - stackurity scan . --git-url "$CI_REPOSITORY_URL"
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH`;
  return { github, gitlab };
}

/**
 * The asset page's note on how the asset reports: a calm "scanned once" note
 * with scheduled-scan snippets, or what stopped and how to fix it.
 */
export function ReportingNotice({ asset }: { asset: Asset }) {
  const r = asset.reporting;
  if (!r || asset.collection_status === "removed") return null;
  const noun = assetNoun(asset.kind);
  if (r.mode === "one_off") {
    const asOf = r.as_of ?? asset.last_seen;
    const age = daysSince(asOf);
    const { github, gitlab } = scheduledSnippets(window.location.origin);
    const scanned = r.override === "one_off" ? "Set to one-off" : `Scanned once on ${shortDate(asOf)}`;
    return (
      <Notice kind="info">
        <strong>{scanned}.</strong> Results stay as of {shortDate(asOf)}
        {age >= ONE_OFF_AGING_DAYS && <> and are {age} days old</>}. Nothing more is expected from this {noun}, so it is not marked stale and
        no alert is raised. Set up a scheduled scan to keep it current.
        <details className="reporting-snippets">
          <summary>Scan it on a schedule</summary>
          <p>
            Save a collector token as the CI secret <span className="mono">STACKURITY_TOKEN</span> (
            <Link to="/settings/integrations">Settings → Integrations → CI pipeline</Link>).
          </p>
          <CodeBlock text={github} label="GitHub Actions workflow" />
          <CodeBlock text={gitlab} label="GitLab CI job (add a pipeline schedule)" />
          <p className="small">
            <Link to="/help/asset-reporting#one-off">How reporting works</Link>
          </p>
        </details>
      </Notice>
    );
  }
  if (asset.collection_status !== "stale") return null;
  if (r.mode === "agent") {
    const win = (asset.attributes?.os_name ?? "").toLowerCase().includes("windows");
    return (
      <Notice kind="warn">
        <strong>The Stackurity agent hasn't reported since {shortDate(asset.last_seen)}.</strong> This is about Stackurity's view of the {noun}.
        Your services may be fine. Findings are not refreshed, and the last results are kept, marked stale. Likely causes: the server is off or was
        rebuilt, the agent service stopped, or it can't reach {window.location.origin}. Fix:{" "}
        {win ? (
          <>check the scheduled task (or service wrapper) that runs <span className="mono">stackurity.exe agent</span> and run it by hand to see the error.</>
        ) : (
          <>
            run <span className="mono">systemctl status stackurity-agent</span> and <span className="mono">journalctl -u stackurity-agent -n 50</span>;
            restart with <span className="mono">systemctl restart stackurity-agent</span>.
          </>
        )}{" "}
        <Link to="/help/asset-reporting#servers">More</Link>
      </Notice>
    );
  }
  if (r.mode === "integration") {
    return (
      <Notice kind="info">
        <strong>No longer seen by its integration</strong> since {shortDate(asset.last_seen)}. If the integration runs, the {noun} is probably gone
        from its source: delete it here. A failing integration has its own problem under Settings → Integrations. Its last results are kept, marked
        stale.
      </Notice>
    );
  }
  const usual = r.usual_seconds ? ` (usually every ${everyText(r.usual_seconds)})` : r.override !== "auto" ? ` (expected ${r.override})` : "";
  return (
    <Notice kind="warn">
      <strong>
        Not scanned since {shortDate(asset.last_seen)}
        {usual}.
      </strong>{" "}
      Your services may be fine; this is about Stackurity's view. Findings are not refreshed, and the last results are kept, marked stale. Likely
      cause: the CI job or scheduled scan that uploads it stopped or failed. Fix: check its last pipeline run. Scan commands are in{" "}
      <Link to="/settings/integrations">Settings → Integrations → CI pipeline</Link>. If it is only scanned now and then, set its reporting to one-off
      below. <Link to="/help/asset-reporting#scans">More</Link>
    </Notice>
  );
}

/** How often an asset may be set to report (asset settings). */
export const REPORTING_OVERRIDES: { value: "auto" | "daily" | "weekly" | "one_off"; label: string }[] = [
  { value: "auto", label: "Automatic (learned from its reports)" },
  { value: "daily", label: "Daily (overdue after 2 days)" },
  { value: "weekly", label: "Weekly (overdue after 8 days)" },
  { value: "one_off", label: "One-off or manual (never overdue)" },
];

/** "Expected: …" for the asset's details. */
export function reportingSummary(asset: Asset): string {
  const r = asset.reporting;
  if (!r) return "";
  const source = { agent: "the agent", scan: "scan uploads", integration: "an integration", manual: "manual uploads", "": "" }[r.source];
  switch (r.mode) {
    case "one_off":
      return `Scanned once (as of ${shortDate(r.as_of ?? asset.last_seen)}); no further report expected`;
    case "unknown":
      return "No report yet";
  }
  const due = r.due_after_seconds ? `, overdue after ${everyText(r.due_after_seconds)}` : "";
  const usual = r.usual_seconds ? `, usually every ${everyText(r.usual_seconds)}` : "";
  return `Reports through ${source}${usual}${due}`;
}
