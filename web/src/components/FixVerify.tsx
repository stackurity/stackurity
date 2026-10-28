import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router";
import { api, type ApiError, type CheckOption, type Finding, type FixGroup, type List } from "../api";
import { useAuth } from "../auth";
import { useAction, useLoad } from "../hooks";
import { absTime, plural } from "../format";
import { CodeBlock, ErrorBox, RelativeTime } from "./ui";

/**
 * "I've fixed it — check now": Stackurity closes issues only from evidence,
 * the next collection. This asks every place a fix covers for a fresh one
 * (the agent reports within a minute; a connected repository is scanned
 * again), shows that it is waiting, and then what the new scan found:
 * fixed, or what is still there and where. Places that cannot report on
 * demand (CI scans, uploads, older agents) say what to do instead.
 */

/** A place a fix covers: its own fix group on one asset. */
export interface VerifyPlace {
  group_id: string;
  asset_id: number;
  asset_name: string;
}

export function fixPlaces(g: FixGroup): VerifyPlace[] {
  if (g.places && g.places.length > 1) return g.places.map((p) => ({ group_id: p.group_id, asset_id: p.asset_id, asset_name: p.asset_name }));
  return [{ group_id: g.id, asset_id: g.asset_id, asset_name: g.asset_name }];
}

/** Results older than this are not shown on cards (the fix detail shows them). */
const RECENT_MS = 24 * 60 * 60 * 1000;
const POLL_MS = 10_000;
const CHUNK = 50;

export type CheckOptions = {
  byGroup: Map<string, CheckOption>;
  error: ApiError | null;
  reload: () => void;
  loaded: boolean;
};

function pending(o: CheckOption | undefined): boolean {
  return Boolean(o?.last_check && o.last_check.status !== "done");
}

/**
 * Check options for many fix groups in as few requests as possible (a list
 * page loads them once), polled every 10 seconds while a check waits.
 */
export function useCheckOptions(groupIds: string[]): CheckOptions {
  const key = [...new Set(groupIds)].sort().join(",");
  const res = useLoad(async () => {
    const ids = key ? key.split(",") : [];
    const chunks: string[][] = [];
    for (let i = 0; i < ids.length; i += CHUNK) chunks.push(ids.slice(i, i + CHUNK));
    const lists = await Promise.all(chunks.map((c) => api.get<{ items: CheckOption[] }>("/checks/options", { fix_group: c.join(",") })));
    return lists.flatMap((l) => l.items);
  }, [key]);
  const byGroup = useMemo(() => new Map((res.data ?? []).map((o) => [o.fix_group ?? "", o])), [res.data]);
  const waiting = (res.data ?? []).some(pending);
  const { reload } = res;
  useEffect(() => {
    if (!waiting) return;
    const t = setInterval(reload, POLL_MS);
    return () => clearInterval(t);
  }, [waiting, reload]);
  return { byGroup, error: res.error, reload, loaded: Boolean(res.data) };
}

/** Where the evidence comes from, in words: "DBC" for an app on it. */
function source(o: CheckOption): string {
  return o.host_name || o.asset_name;
}

function when(iso: string | null | undefined): ReactNode {
  return iso ? <time dateTime={iso}>{absTime(iso)}</time> : null;
}

/** What is still found for one place after a check: version and location of its open issues. */
function StillThere({ o }: { o: CheckOption }) {
  const res = useLoad(
    () => api.get<List<Finding>>("/findings", { fix_group: o.fix_group, status: "open", limit: 50 }),
    [o.fix_group, o.last_check?.id],
  );
  const seen = new Map<string, Finding>();
  for (const f of res.data?.items ?? []) {
    const k = `${f.component_name}@${f.version}@${f.location}`;
    if (!seen.has(k)) seen.set(k, f);
  }
  const rows = [...seen.values()];
  if (rows.length === 0) return null;
  return (
    <ul className="plain-list small verify-left">
      {rows.slice(0, 3).map((f) => (
        <li key={f.id}>
          <span className="mono break">
            {f.component_name} {f.version}
          </span>
          {f.location && (
            <>
              {" "}
              at <span className="mono break">{f.location}</span>
            </>
          )}
        </li>
      ))}
      {rows.length > 3 && <li className="muted">and {rows.length - 3} more</li>}
    </ul>
  );
}

/** One place's state: waiting, the result of the last check, or why it cannot be checked on demand. */
function PlaceState({ o, recentOnly, many }: { o: CheckOption; recentOnly: boolean; many: boolean }) {
  const c = o.last_check;
  const where = many ? <strong>{o.asset_name}</strong> : null;
  if (c && c.status !== "done") {
    return (
      <p className="small verify-pending" role="status">
        <span className="spinner" aria-hidden="true" />
        {where}
        {where && ": "}
        {c.method === "integration" ? (
          <>Scanning {o.asset_name} again… this takes a minute or two.</>
        ) : c.status === "evaluating" ? (
          <>The new scan of {source(o)} arrived; checking it now…</>
        ) : c.method === "agent" ? (
          <>Checking {source(o)}… usually within a minute.</>
        ) : (
          <>Waiting for the next scan of {o.asset_name}.</>
        )}
      </p>
    );
  }
  const recent = c?.completed_at && Date.now() - new Date(c.completed_at).getTime() < RECENT_MS;
  if (c && c.status === "done" && (recent || !recentOnly)) {
    switch (c.outcome) {
      case "passed":
        return (
          <p className="small verify-ok" role="status">
            {where}
            {where && ": "}
            Fixed, confirmed by a new scan of {source(o)} at {when(c.completed_at)}.
          </p>
        );
      case "partly_fixed":
      case "still_open":
        return (
          <div className="small verify-left-wrap" role="status">
            <p className="verify-bad">
              {where}
              {where && ": "}
              {c.outcome === "partly_fixed" ? `Partly fixed (${c.fixed.toLocaleString()} gone). ` : ""}
              Still found on {source(o)} by the scan at {when(c.completed_at)}:
            </p>
            <StillThere o={o} />
          </div>
        );
      case "incomplete":
        return (
          <p className="small verify-bad" role="status">
            {where}
            {where && ": "}
            The scan of {source(o)} at {when(c.completed_at)} could not read everything, so what is left could not be confirmed gone.{" "}
            <Link to={`/assets/${o.asset_id}?tab=coverage`}>See what it could not read</Link>.
          </p>
        );
      case "expired":
        return (
          <p className="small muted">
            {where}
            {where && ": "}
            The last check got no report within 7 days.
          </p>
        );
    }
  }
  if (o.on_demand) return null;
  return <NotOnDemand o={o} where={where} compact={recentOnly} />;
}

/** Why a place cannot be checked now, and what to do instead. */
function NotOnDemand({ o, where, compact }: { o: CheckOption; where: ReactNode; compact: boolean }) {
  const lead = (
    <>
      {where}
      {where && ": "}
    </>
  );
  if (compact) {
    // Cards: one line; the fix's page has the commands.
    const line: Record<string, ReactNode> = {
      removed: <>{o.app_dir ? <span className="mono">{o.app_dir}</span> : o.asset_name} is no longer on {o.host_name || "its server"}.</>,
      agent: (
        <>
          The agent on {source(o)} reports every 6 hours (last <RelativeTime iso={o.last_seen} />) and does not take check requests: restart it
          to report now.
        </>
      ),
      upload:
        o.asset_kind === "repository" ? (
          <>{o.asset_name} is scanned in CI: after merging the fix, re-run the pipeline.</>
        ) : (
          <>{o.asset_name} was uploaded: upload the new scan or SBOM after the fix.</>
        ),
    };
    const l = o.reason ? line[o.reason] : null;
    return l ? (
      <p className="small muted">
        {lead}
        {l}
      </p>
    ) : null;
  }
  switch (o.reason) {
    case "removed":
      return (
        <p className="small muted">
          {lead}
          {o.app_dir ? <span className="mono">{o.app_dir}</span> : o.asset_name} is no longer on {o.host_name || "its server"}; its issues closed as
          removed.
        </p>
      );
    case "agent":
      return (
        <div className="small">
          <p>
            {lead}
            The agent on {source(o)} does not take check requests (it is older than 0.7, or not running): it reports every 6 hours, last{" "}
            <RelativeTime iso={o.last_seen} />. To report now, restart it on the server, or upgrade it so this works within a minute:
          </p>
          <CodeBlock label="Report now" text="sudo systemctl restart stackurity-agent" />
        </div>
      );
    case "upload":
      if (o.asset_kind === "repository")
        return (
          <div className="small">
            <p>
              {lead}
              {o.asset_name} is scanned in CI: merge the fix, then re-run the pipeline (or scan it yourself with a collector token in{" "}
              <span className="mono">STACKURITY_TOKEN</span>). The issues close when that scan no longer finds them.
            </p>
            <CodeBlock label="Scan now" text={`stackurity scan . --git-url "${o.git_url || "$CI_REPOSITORY_URL"}"`} />
          </div>
        );
      if (o.asset_kind === "image")
        return (
          <p className="small">
            {lead}Build and push the fixed image, then scan it again (<span className="mono">stackurity scan-image</span> in CI). The issues close
            when the new scan no longer finds them.
          </p>
        );
      return (
        <p className="small">
          {lead}
          {o.asset_name} was uploaded (an SBOM or a scan): upload the new one after the fix. The issues close when it no longer lists them.
        </p>
      );
    default:
      return null;
  }
}

/**
 * The verify block on a fix card or the fix detail: the button, the
 * pending state, and each place's result or what to do instead.
 * recentOnly hides results older than a day (cards).
 */
export function FixVerify({
  g,
  options,
  recentOnly = true,
  onChecked,
}: {
  g: FixGroup;
  options: CheckOptions;
  recentOnly?: boolean;
  onChecked?: () => void;
}) {
  const { canAct } = useAuth();
  const act = useAction();
  const [asked, setAsked] = useState(false);
  const places = fixPlaces(g);
  const opts = places.map((p) => options.byGroup.get(p.group_id)).filter((o): o is CheckOption => Boolean(o));
  if (!options.loaded && !options.error) return null;
  const many = places.length > 1;
  const checkable = opts.filter((o) => o.on_demand);
  const waiting = opts.some(pending);
  const hosts = [...new Set(checkable.map(source))];
  const run = async () => {
    // "I applied this" for each place: its issues show as applied, waiting
    // for a check, and its agent (or integration) is asked to report now.
    const ok = await act.run(() => Promise.all(checkable.map((o) => api.post(`/fix-groups/${encodeURIComponent(o.fix_group ?? "")}/applied`))));
    if (ok) {
      setAsked(true);
      options.reload();
      onChecked?.();
    }
  };
  const states = opts.map((o) => <PlaceState key={o.fix_group} o={o} recentOnly={recentOnly && !asked} many={many} />);
  const canAsk = canAct("engineer") && checkable.length > 0;
  return (
    <div className="fix-verify" aria-live="polite">
      {canAsk && !waiting && (
        <div className="fix-verify-ask">
          <button type="button" className="btn btn-sm" disabled={act.pending} onClick={run}>
            {act.pending ? "Asking…" : "I've fixed it — check now"}
          </button>
          <span className="small muted">
            Asks {hosts.length === 1 ? `${hosts[0]}` : plural(hosts.length, "source")} for a new scan
            {many && checkable.length < places.length ? ` (${checkable.length} of ${places.length} places)` : ""}. Issues close only when it no
            longer finds them.
          </span>
        </div>
      )}
      {states}
      <ErrorBox error={act.error ?? options.error} title="Could not ask for a new scan" />
    </div>
  );
}
