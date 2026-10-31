import { useState } from "react";
import { api } from "../../api";
import { useLoad } from "../../hooks";
import { Badge } from "../../components/Badge";
import { Table, type Column } from "../../components/Table";
import { Card, EmptyState, ErrorBox, Loading, PageHeader, RelativeTime, StatTile, Tabs } from "../../components/ui";
import { assetKindLabel, plural } from "../../format";
import {
  STATE_LABEL,
  STATE_TONE,
  filterOrgs,
  flagLabel,
  share,
  timeToFirst,
  weekLabel,
  type TrialCohort,
  type TrialFilter,
  type TrialOrg,
  type TrialReport,
} from "../../trials";

function cohortColumns(): Column<TrialCohort>[] {
  return [
    { key: "week", header: "Signed up", cell: (c) => weekLabel(c.week) },
    { key: "signed_up", header: "Sign-ups", numeric: true, cell: (c) => c.signed_up },
    { key: "activated", header: "Connected an asset", numeric: true, cell: (c) => share(c.activated, c.signed_up) },
    { key: "active_7d", header: "Active last 7 days", numeric: true, cell: (c) => share(c.active_7d, c.signed_up) },
    { key: "converted", header: "Paid", numeric: true, cell: (c) => share(c.converted, c.signed_up) },
    { key: "trialing", header: "In trial", numeric: true, cell: (c) => c.trialing },
    { key: "expired", header: "Ended unpaid", numeric: true, cell: (c) => c.expired },
    { key: "cancelled", header: "Cancelled", numeric: true, cell: (c) => c.cancelled },
  ];
}

function orgColumns(quietDays: number): Column<TrialOrg>[] {
  return [
    {
      key: "name",
      header: "Organisation",
      cell: (o) => (
        <>
          {o.name} <span className="muted small">#{o.workspace_id}</span>
          <div className="small muted">{plural(o.members, "member")}</div>
        </>
      ),
    },
    {
      key: "signed_up",
      header: "Signed up",
      cell: (o) => (
        <>
          <RelativeTime iso={o.signed_up_at} />
          <div className="small muted">
            {new Date(o.trial_ends_at).getTime() > Date.now() ? "trial ends " : "trial ended "}
            <RelativeTime iso={o.trial_ends_at} />
          </div>
        </>
      ),
    },
    {
      key: "state",
      header: "State",
      cell: (o) => (
        <>
          <Badge status={o.state} tone={STATE_TONE[o.state]} label={STATE_LABEL[o.state]} title={`Billing: ${o.billing_status}`} />
          {o.disabled && <div className="small muted">disabled</div>}
        </>
      ),
    },
    {
      key: "first_asset",
      header: "First asset",
      cell: (o) =>
        o.first_asset_at ? (
          <>
            {o.first_asset_kind ? assetKindLabel(o.first_asset_kind) : "collection"}, after {timeToFirst(o.hours_to_first_asset)}
            <div className="small muted">
              {plural(o.assets, "asset")} ({plural(o.hosts, "host")}, {plural(o.repositories, "repository", "repositories")})
            </div>
          </>
        ) : (
          <span className="muted">none</span>
        ),
    },
    {
      key: "last_sign_in",
      header: "Last sign-in",
      cell: (o) => <RelativeTime iso={o.last_sign_in_at ?? o.last_seen_at} />,
    },
    {
      key: "last_collection",
      header: "Last collection",
      cell: (o) => <RelativeTime iso={o.last_collection_at ?? o.last_agent_check_in_at} />,
    },
    {
      key: "active",
      header: "Active",
      cell: (o) => (o.active_7d ? "last 7 days" : o.active_30d ? "last 30 days" : <span className="muted">not in 30 days</span>),
    },
    {
      key: "flags",
      header: "Flags",
      cell: (o) =>
        o.flags.length === 0 ? null : (
          <span className="small">{o.flags.map((f) => flagLabel(f, quietDays)).join("; ")}</span>
        ),
    },
  ];
}

const FILTERS: { id: TrialFilter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "trialing", label: "In trial" },
  { id: "flagged", label: "Flagged" },
  { id: "converted", label: "Paying" },
  { id: "ended", label: "Ended or cancelled" },
];

/**
 * Instance administration on Stackurity Cloud: organisations that started
 * a trial, by the week they signed up, whether they connected anything,
 * whether anyone still uses them, and whether they paid. Read only.
 */
export function TrialsPage() {
  const res = useLoad(() => api.get<TrialReport>("/admin/trials"), []);
  const [filter, setFilter] = useState<TrialFilter>("all");
  const [cohort, setCohort] = useState("");
  const d = res.data;
  const t = d?.totals;
  const orgs = d ? filterOrgs(d.orgs, filter, cohort) : [];
  return (
    <>
      <PageHeader
        title="Trials"
        sub="Organisations that signed up on Stackurity Cloud, by the week they signed up: whether they connected an asset, still use Stackurity and paid. Activity is sign-ins, dashboard use, collections, agent check-ins and API use by members; instance administrators are not counted."
        actions={
          <button type="button" className="btn" onClick={res.reload}>
            Refresh
          </button>
        }
      />
      <ErrorBox error={res.error} title="Could not load the trial report" />
      {!d && !res.error && <Loading />}
      {d && t && (
        <>
          <div className="tiles">
            <StatTile label="Signed up" value={t.signed_up} sub={`${t.trialing} in trial now`} />
            <StatTile label="Connected an asset" value={share(t.activated, t.signed_up)} sub={`${t.never_activated} never did`} />
            <StatTile
              label="Active last 7 days"
              value={share(t.active_7d, t.signed_up)}
              sub={`${plural(t.went_quiet, "trial")} quiet for ${d.quiet_days}+ days`}
              tone={t.went_quiet > 0 ? "warn" : undefined}
            />
            <StatTile label="Paid" value={share(t.converted, t.signed_up)} sub={`${t.expired} ended unpaid, ${t.cancelled} cancelled`} />
          </div>
          <p className="small muted">
            As of <RelativeTime iso={d.generated_at} />.{" "}
            {d.excluded.length > 0
              ? `Not counted: workspaces ${d.excluded.join(", ")} (the operator's own and test organisations).`
              : "No organisation is left out."}{" "}
            Organisations deleted after 30 days read-only are no longer listed.
          </p>
          <Card title="By sign-up week">
            {d.cohorts.length === 0 ? (
              <EmptyState title="No organisation has signed up yet" />
            ) : (
              <Table
                columns={cohortColumns()}
                rows={d.cohorts}
                rowKey={(c) => c.week}
                caption="Sign-ups by week"
                onRowClick={(c) => setCohort(cohort === c.week ? "" : c.week)}
                selectedKey={cohort || null}
              />
            )}
          </Card>
          <Card
            title={cohort ? `Organisations, ${weekLabel(cohort).toLowerCase()}` : "Organisations"}
            actions={
              cohort ? (
                <button type="button" className="btn btn-sm" onClick={() => setCohort("")}>
                  All weeks
                </button>
              ) : undefined
            }
          >
            <Tabs tabs={FILTERS} value={filter} onChange={setFilter} label="Show" />
            {orgs.length === 0 ? (
              <EmptyState title="No organisation matches" />
            ) : (
              <Table columns={orgColumns(d.quiet_days)} rows={orgs} rowKey={(o) => o.workspace_id} caption="Organisations" />
            )}
          </Card>
        </>
      )}
    </>
  );
}
