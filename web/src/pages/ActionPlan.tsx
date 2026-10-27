import { useEffect, useState } from "react";
import { Link, useLocation, useParams, useSearchParams } from "react-router";
import {
  api,
  FIX_BUCKETS,
  FIX_GROUP_KINDS,
  PRIORITIES,
  SEVERITIES,
  type Asset,
  type AssetDetail,
  type Check,
  type FixBucket,
  type FixGroup,
  type FixGroupDetail,
  type FixGroupSummary,
  type List,
} from "../api";
import { useAuth } from "../auth";
import { useAction, useDebounced, useFacets, useLoad } from "../hooks";
import { plural } from "../format";
import { FindingCards, FindingsTable } from "../components/Findings";
import {
  ActionInstruction,
  BreakdownBar,
  changeText,
  FIX_KIND_HELP,
  FIX_KIND_LABEL,
  fixesFrom,
  FixGroupCard,
  FixKindIcon,
  GroupBadges,
  PRIO_CLASS,
  SEV_CLASS,
  urgencyOf,
  versionsText,
} from "../components/FixGroups";
import { Badge } from "../components/Badge";
import { assignGroup, FindingActions, GROUP_ACTION_MAX } from "../components/Workflow";
import { CheckAgain, CheckBadge, CheckResultText } from "../components/CheckAgain";
import { Card, EmptyState, ErrorBox, FilterPanel, Loading, Notice, PageHeader, Pager, PresetChips, RelativeTime } from "../components/ui";

const LIMIT = 20;

/** Plain-language names of the fix buckets (store.FixBuckets). */
export const BUCKET_LABEL: Record<FixBucket, string> = {
  focus: "Needs you",
  no_fix: "No fix yet",
  old_kernels: "Old kernels",
  non_production: "Not production",
  lower_priority: "Lower priority",
};

const BUCKET_HELP: Record<FixBucket, string> = {
  focus: "",
  no_fix: "No source lists a free fixed version yet. These come back as fixes when one is published; meanwhile mitigate or accept the risk.",
  old_kernels: "Kernels that are installed but not running. Removing them clears these issues; they are not exploitable while unused.",
  non_production: "Fixes on assets whose environment is not a production one in the risk policy.",
  lower_priority: "Fixes whose most urgent issue is P2 to P4 and matches no SOS rule.",
};

/** Fix cards for an asset (used on asset detail) or for everything. */
export function FixGroupList({
  assetId,
  kind,
  environment,
  q,
  bucket,
  compactEmpty,
}: {
  assetId?: number;
  kind?: string;
  environment?: string;
  q?: string;
  bucket?: string;
  compactEmpty?: boolean;
}) {
  const [offset, setOffset] = useState(0);
  useEffect(() => setOffset(0), [assetId, kind, environment, q, bucket]);
  const res = useLoad(
    // The same upgrade on several assets in view is one card (merge).
    () => api.get<List<FixGroup>>("/fix-groups", { asset_id: assetId, kind, environment, q, bucket, merge: true, limit: LIMIT, offset }),
    [assetId, kind, environment, q, bucket, offset],
  );
  return (
    <>
      <ErrorBox error={res.error} title="Could not load the fixes" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && (
        <EmptyState title={kind || environment || q || bucket ? "No fixes match these filters" : "Nothing to fix"} help="action-plan">
          {!compactEmpty && (
            <p>
              No open issues need a change. That covers only what was inventoried and checked; see <Link to="/coverage">Coverage</Link>{" "}
              and <Link to="/intelligence">Intelligence</Link> for gaps.
            </p>
          )}
        </EmptyState>
      )}
      {res.data && res.data.items.length > 0 && (
        <>
          <div className="fix-list">
            {res.data.items.map((g) => (
              <FixGroupCard key={g.id} g={g} hideAsset={Boolean(assetId)} />
            ))}
          </div>
          <Pager total={res.data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
    </>
  );
}

/** Fixes: every change to make, one card per fix, most urgent first. */
export function FixesPage() {
  const [params, setParams] = useSearchParams();
  const assetId = params.get("asset_id") ?? "";
  const kind = params.get("kind") ?? "";
  const environment = params.get("environment") ?? "";
  const bucket = params.get("bucket") ?? "";
  const qParam = params.get("q") ?? "";
  const [q, setQ] = useState(qParam);
  const dq = useDebounced(q);
  const facets = useFacets();
  const assets = useLoad(() => api.get<List<Asset>>("/assets", { limit: 200 }), []);
  const summary = useLoad(() => api.get<FixGroupSummary>("/fix-groups/summary", { asset_id: assetId, merge: true }), [assetId]);

  const with_ = (patch: Record<string, string>) => {
    const n = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v) n.set(k, v);
      else n.delete(k);
    }
    return n;
  };
  const update = (patch: Record<string, string>) => setParams(with_(patch), { replace: true });
  const link = (patch: Record<string, string>) => {
    const str = with_(patch).toString();
    return `/fixes${str ? `?${str}` : ""}`;
  };
  useEffect(() => {
    if (dq !== qParam) update({ q: dq });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dq]);
  useEffect(() => setQ(qParam), [qParam]);

  const active = [assetId, kind, environment, qParam].filter(Boolean).length;
  const s = summary.data;
  const focus = s?.focus;
  const bucketCount = (b: FixBucket) => (b === "focus" ? focus?.groups : focus?.hidden?.[b]?.groups) ?? 0;

  return (
    <>
      <PageHeader
        help="action-plan"
        title="Fixes"
        sub="Each fix is one change, such as an upgrade, that clears one or more issues. Most urgent first; open a fix for the steps."
      />
      <ErrorBox error={summary.error} title="Could not load the summary" />
      {s && (
        <p className="lead-line">
          {focus && (
            <>
              <Link to={link({ bucket: "focus" })}>
                <strong>
                  {plural(focus.groups, "fix", "fixes")} {focus.groups === 1 ? "needs" : "need"} you
                </strong>
              </Link>
              {" · "}
            </>
          )}
          <Link to={link({ bucket: "" })}>{plural(s.groups, "fix", "fixes")} in all</Link>, clearing{" "}
          <Link to={assetId ? `/fixes/issues?asset_id=${assetId}` : "/fixes/issues"}>{plural(s.findings, "issue")}</Link>
          {assetId && <span className="muted"> on this asset</span>}
        </p>
      )}
      <PresetChips
        label="Show"
        chips={[
          { to: link({ bucket: "" }), label: <>All fixes{s ? ` (${s.groups.toLocaleString()})` : ""}</>, active: !bucket },
          ...FIX_BUCKETS.filter((b) => b === "focus" || bucketCount(b) > 0 || bucket === b).map((b) => ({
            to: link({ bucket: b }),
            label: (
              <>
                {BUCKET_LABEL[b]}
                {focus ? ` (${bucketCount(b).toLocaleString()})` : ""}
              </>
            ),
            active: bucket === b,
          })),
        ]}
      />
      <FilterPanel
        active={active}
        onClear={() => {
          setQ("");
          setParams(bucket ? new URLSearchParams({ bucket }) : new URLSearchParams(), { replace: true });
        }}
      >
        <div className="field">
          <label htmlFor="ap-q">Search</label>
          <input id="ap-q" type="search" placeholder="Package, OS or title" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="ap-asset">Asset</label>
          <select id="ap-asset" value={assetId} onChange={(e) => update({ asset_id: e.target.value })}>
            <option value="">All assets</option>
            {assets.data?.items.map((a) => (
              <option key={a.id} value={String(a.id)}>
                {a.name}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="ap-env">Environment</label>
          <select id="ap-env" value={environment} onChange={(e) => update({ environment: e.target.value })}>
            <option value="">Any environment</option>
            {(facets?.environments ?? []).map((x) => (
              <option key={x} value={x}>
                {x}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="ap-kind">Kind of fix</label>
          <select id="ap-kind" value={kind} onChange={(e) => update({ kind: e.target.value })}>
            <option value="">All kinds</option>
            {FIX_GROUP_KINDS.map((k) => (
              <option key={k} value={k}>
                {FIX_KIND_LABEL[k]}
              </option>
            ))}
          </select>
        </div>
      </FilterPanel>
      {bucket && BUCKET_HELP[bucket as FixBucket] && <p className="hint">{BUCKET_HELP[bucket as FixBucket]}</p>}
      {kind && <p className="hint">{FIX_KIND_HELP[kind]}</p>}
      <FixGroupList assetId={assetId ? Number(assetId) : undefined} kind={kind} environment={environment} q={qParam} bucket={bucket} />
    </>
  );
}

const DETAIL_LIMIT = 50;

export function FixGroupDetailPage() {
  const { id = "" } = useParams();
  const { hash } = useLocation();
  const { canAct } = useAuth();
  // Links in notifications (Assign to me, Snooze) open the fix with the
  // action ready: ?action=assign asks for one tap to confirm, ?action=snooze
  // opens the snooze form. Opening a link never changes anything.
  const [params, setParams] = useSearchParams();
  const linkAction = params.get("action");
  const [offset, setOffset] = useState(0);
  useEffect(() => setOffset(0), [id]);
  const res = useLoad(
    () => api.get<FixGroupDetail>(`/fix-groups/${encodeURIComponent(id)}`, { limit: DETAIL_LIMIT, offset }),
    [id, offset],
  );
  const assetId = res.data?.group.asset_id;
  const asset = useLoad(() => (assetId ? api.get<AssetDetail>(`/assets/${assetId}`) : Promise.resolve(null)), [assetId]);
  const initialPanel =
    hash === "#assign" ? "assign" : hash === "#snooze" || linkAction === "snooze" ? "suppress" : hash === "#accept" ? "accept_risk" : undefined;
  const clearAction = () => {
    const q = new URLSearchParams(params);
    q.delete("action");
    setParams(q, { replace: true });
  };
  const loaded = Boolean(res.data);
  useEffect(() => {
    if (initialPanel && loaded) document.getElementById("fix-act")?.scrollIntoView({ block: "start" });
  }, [initialPanel, loaded]);

  if (res.error && res.error.status === 404) return <FixDone id={id} />;
  if (res.error)
    return (
      <>
        <PageHeader help="action-plan" title="Fix" />
        <ErrorBox error={res.error} title="Could not load this fix" />
        <p>
          <Link to="/fixes">Back to fixes</Link>
        </p>
      </>
    );
  if (!res.data) return <Loading />;
  const g = res.data.group;
  const page = res.data.findings?.items ?? [];
  const total = res.data.findings?.total ?? 0;
  const versions = versionsText(g) || null;
  const from = fixesFrom(g);
  const issuesLink = `/fixes/issues?fix_group=${encodeURIComponent(g.id)}`;
  const u = urgencyOf(g);
  const locations = [...new Set(page.map((f) => f.location).filter(Boolean))];
  const why =
    g.known_exploited > 0
      ? `${plural(g.known_exploited, "of them is", "of them are")} known to be exploited by attackers.`
      : g.sos
        ? "It matches an SOS rule in your risk policy."
        : `The most urgent of them is ${g.top_priority}.`;

  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/fixes">Fixes</Link> <span aria-hidden="true">/</span> <span>{FIX_KIND_LABEL[g.kind] ?? g.kind}</span>
      </nav>
      <PageHeader
        help="action-plan"
        title={
          <span className="badges">
            <span className="fix-icon fix-icon-inline">
              <FixKindIcon kind={g.kind} />
            </span>
            <span className="break">{g.title}</span>
          </span>
        }
        sub={
          <span className="badges">
            <Badge status={`urgency-${u.label}`} tone={u.tone} label={u.label} title={u.title} />
            <span>
              {g.asset_name} · {plural(g.finding_count, "issue")} · {changeText(g)}
            </span>
          </span>
        }
      />

      {linkAction === "assign" && <AssignToMe group={g} onDone={() => { clearAction(); res.reload(); }} onCancel={clearAction} />}

      <section className="card fix-what" aria-label="What and why">
        <p className="fix-what-line">
          {g.kind === "no_fix" ? (
            <>
              No source lists a free fixed version for these {plural(g.finding_count, "issue")} on <strong>{g.asset_name}</strong> yet.
            </>
          ) : (
            <>
              This clears {plural(g.finding_count, "issue")} on <strong>{g.asset_name}</strong>
              {g.unique_issues !== undefined && g.unique_issues !== g.finding_count
                ? ` (${plural(g.unique_issues, "distinct vulnerability", "distinct vulnerabilities")})`
                : ""}
              .
            </>
          )}{" "}
          {why}
        </p>
        {FIX_KIND_HELP[g.kind] && <p className="hint">{FIX_KIND_HELP[g.kind]}</p>}
      </section>

      <div className="grid-2">
        <Card title="Where">
          <p>
            <Link to={`/assets/${g.asset_id}`}>{g.asset_name}</Link>
            <span className="muted"> · {g.environment || "no environment"}</span>
          </p>
          {g.component && (
            <p className="small">
              Component <span className="mono break">{g.component}</span>
              {versions && (
                <>
                  , <span className="mono break">{versions}</span>
                  {from && <span className="muted"> ({from})</span>}
                </>
              )}
            </p>
          )}
          {locations.length > 0 && (
            <>
              <p className="small muted fix-found-in">Found in</p>
              <ul className="plain-list small">
                {locations.slice(0, 8).map((l) => (
                  <li key={l} className="mono break">
                    {l}
                  </li>
                ))}
                {locations.length > 8 && <li className="muted">and {locations.length - 8} more on this page</li>}
              </ul>
            </>
          )}
          {g.packages && g.packages.length > 0 && (
            <details className="fix-packages">
              <summary>
                {plural(g.package_count, "package")}
                {g.package_count > g.packages.length ? `, first ${g.packages.length} shown` : ""}
              </summary>
              <p className="chips">
                {g.packages.map((p) => (
                  <span key={p} className="chip mono">
                    {p}
                  </span>
                ))}
              </p>
            </details>
          )}
          <CheckAgain asset={asset.data?.asset} fixGroup={g.id} onChanged={res.reload} />
        </Card>
        <Card title="How to fix">
          <div className="form-compact form">
            <ActionInstruction action={g.action} />
            {g.note && <p className="hint">{g.note}</p>}
            <p className="small">
              <strong>Change:</strong> {changeText(g)}
              {g.effort && <span className="muted"> · {g.effort} effort</span>}
            </p>
            {(g.requires_major || g.change_type === "major") && (
              <Notice kind="warn">
                <strong>Major upgrade.</strong> The fixed version is in a new major release, which can change behaviour. Test it before
                rolling it out.
              </Notice>
            )}
            {g.recommended_version && g.recommended_version !== g.to_version && (
              <p className="small">
                {g.target_version === g.recommended_version ? (
                  <>
                    <strong>Why {g.recommended_version}:</strong> it is the newest stable release in that line. Any version from{" "}
                    <span className="mono">{g.to_version}</span> fixes these issues.
                  </>
                ) : (
                  <>
                    <strong>Recommended:</strong> <span className="mono">{g.recommended_version}</span>, the newest stable release in that line.
                  </>
                )}
                {g.rationale && g.rationale.length > 0 && <span className="muted"> {g.rationale.join(" ")}</span>}
              </p>
            )}
            {g.recommended_yanked && <Notice kind="warn">The recommended version was withdrawn by its publisher; pick the next release.</Notice>}
            <GroupBadges g={g} />
          </div>
        </Card>
      </div>

      <h2 className="section-title">Issues this fix clears ({total.toLocaleString()})</h2>
      <BreakdownBar counts={g.by_priority} order={PRIORITIES} classes={PRIO_CLASS} label="By priority" />
      <BreakdownBar counts={g.by_severity} order={SEVERITIES} classes={SEV_CLASS} label="By severity" />
      {page.length === 0 ? (
        <p className="muted">No open issues in this fix.</p>
      ) : (
        <>
          <div className="only-wide">
            <FindingsTable rows={page} hideAsset hideGroup />
          </div>
          <FindingCards rows={page} hideAsset />
          <Pager total={total} limit={DETAIL_LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}

      <section id="fix-act" className="card fix-act" aria-labelledby="fix-act-h">
        <h2 id="fix-act-h">{canAct("security") ? "Assign, snooze or ignore" : "Assign or ask to ignore"}</h2>
        {g.finding_count > GROUP_ACTION_MAX ? (
          <p className="small">
            This fix has {g.finding_count.toLocaleString()} issues, more than can be changed at once here ({GROUP_ACTION_MAX.toLocaleString()}).
            Open <Link to={issuesLink}>its issues in All issues</Link> and select them a page at a time.
          </p>
        ) : (
          <>
            <p className="small muted">
              Applies to all {plural(g.finding_count, "issue")} of this fix. Snoozing and ignoring need the security role and a reason; other
              roles can ask to ignore, and security decides.
            </p>
            <FindingActions target={{ type: "group", id: g.id, count: g.finding_count }} onDone={res.reload} initialPanel={initialPanel} />
          </>
        )}
        {g.finding_count <= GROUP_ACTION_MAX && (
          <p className="small">
            <Link to={issuesLink}>Open these issues in All issues</Link> to filter them or act on some of them.
          </p>
        )}
      </section>
    </>
  );
}

/**
 * Assign to me, from a notification: one tap to confirm, after sign-in.
 */
function AssignToMe({ group, onDone, onCancel }: { group: FixGroup; onDone: () => void; onCancel: () => void }) {
  const { me, canAct } = useAuth();
  const act = useAction();
  const [done, setDone] = useState<string | null>(null);
  const myId = me?.user?.id;
  if (done) return <Notice kind="success">{done}</Notice>;
  if (!myId || !canAct("engineer")) {
    return (
      <Notice kind="warn">
        Assigning fixes needs the engineer role or higher. You can look at this fix; ask an administrator if you should work on it.
      </Notice>
    );
  }
  if (group.finding_count > GROUP_ACTION_MAX) {
    return (
      <Notice kind="info">
        This fix has {group.finding_count.toLocaleString()} issues, more than can be assigned at once here. Open its issues in All issues and assign them a page at a time.
      </Notice>
    );
  }
  const go = async () => {
    const r = await act.run(() => assignGroup(group.id, myId));
    if (r) {
      setDone(`Assigned to you: ${plural(r.applied, "issue")}.${r.failed?.length ? ` ${r.failed.length} could not be changed.` : ""}`);
      onDone();
    }
  };
  return (
    <section className="card confirm-card" aria-labelledby="assign-me-h">
      <h2 id="assign-me-h">Assign this fix to you?</h2>
      <p>
        Its {plural(group.finding_count, "open issue")} on {group.asset_name} will show you as the assignee.
      </p>
      <ErrorBox error={act.error} title="Could not assign" />
      <div className="form-actions">
        <button type="button" className="btn btn-primary" onClick={go} disabled={act.pending} autoFocus>
          {act.pending ? "Assigning…" : "Assign to me"}
        </button>
        <button type="button" className="btn" onClick={onCancel}>
          Not now
        </button>
      </div>
    </section>
  );
}

/**
 * A fix that is no longer in the plan: every issue it was about is gone (or
 * handled). When a check proved it, say so instead of "not found".
 */
function FixDone({ id }: { id: string }) {
  const checks = useLoad(() => api.get<List<Check>>("/checks", { fix_group: id, limit: 1 }), [id]);
  if (!checks.data && !checks.error) return <Loading />;
  const c = checks.data?.items[0];
  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/fixes">Fixes</Link>
      </nav>
      <PageHeader help="check-again" title={c ? (c.fix_title || "This fix") + " is done" : "Fix"} sub={c ? c.asset_name : undefined} />
      {c ? (
        <Card title={<span className="badges">Last check <CheckBadge c={c} /></span>}>
          {c.status === "done" ? (
            <CheckResultText c={c} issuesLink={`/fixes/issues?asset_id=${c.asset_id}`} />
          ) : (
            <p className="small">A check is still waiting for a report.</p>
          )}
          <p className="small">
            This fix is no longer in the plan: none of its issues is open and active any more. Asked by {c.requested_by || "someone"}{" "}
            <RelativeTime iso={c.requested_at} />.
          </p>
          <p className="small">
            <Link to={`/assets/${c.asset_id}`}>Open {c.asset_name}</Link> · <Link to={`/fixes?asset_id=${c.asset_id}`}>Its other fixes</Link> ·{" "}
            <Link to={`/fixes/issues?status=resolved&asset_id=${c.asset_id}`}>Fixed issues</Link>
          </p>
        </Card>
      ) : (
        <>
          <Notice kind="info">This fix is no longer in the plan. Its issues were fixed or handled, or the plan changed.</Notice>
          <p>
            <Link to="/fixes">Back to fixes</Link>
          </p>
        </>
      )}
    </>
  );
}
