import type { ReactNode } from "react";
import { Link, useSearchParams } from "react-router";
import { api, PRIORITIES, type Check, type Finding, type IgnoreRequestList, type Incident, type List, type Plan } from "../api";
import { useAuth } from "../auth";
import { useLoad, type Loaded } from "../hooks";
import { plural } from "../format";
import { Badge, IGNORE_REASON_LABEL, PriorityBadge } from "../components/Badge";
import { CheckBadge } from "../components/CheckAgain";
import { IconCheckCircle } from "../components/Icons";
import { PlanStatusBadge } from "../components/Remediation";
import { ProjectFilter } from "../components/AssetPicker";
import { ProNotice } from "../components/ProNotice";
import { ErrorBox, FilterPanel, Loading, PageHeader, RelativeTime } from "../components/ui";
import {
  activeFilters,
  assignedQuery,
  DEADLINE_LABEL,
  emptyLine,
  failedPlansQuery,
  fullLink,
  incidentsQuery,
  myWorkQuery,
  overdueQuery,
  OWNER_LABEL,
  parseMyWork,
  sectionsFor,
  sectionTitle,
  type Deadline,
  type MyWorkFilters,
  type Owner,
  type SectionId,
} from "../myWork";
import "../styles/my-work.css";

/** Rows shown per section; the link opens the full list. */
const ROWS = 5;

/**
 * Fixes ▸ My work: one place to start the day. Issues assigned to you and
 * your teams, what is overdue, decisions waiting for you, automatic fixes
 * and checks that failed, and open incidents, each as a short list with a
 * count, one action per row and a link to its full page.
 */
export function MyWorkPage() {
  const [params, setParams] = useSearchParams();
  const { can, canAct, has, projectOnly } = useAuth();
  const f = parseMyWork(params);
  const set = (patch: Partial<MyWorkFilters>) => setParams(new URLSearchParams(myWorkQuery({ ...f, ...patch })), { replace: true });
  const sections = sectionsFor({
    canDecide: canAct("security"),
    canApprovePlans: can("security"),
    orgWide: !projectOnly,
    paid: has("remediation"),
  });

  return (
    <div className="ac mw">
      <PageHeader
        help="action-plan"
        title="My work"
        sub="Where to start the day: your issues, what is overdue, decisions waiting for you, and what failed. Each list shows the first few; open the full page for the rest."
        actions={
          <Link className="btn" to="/fixes">
            All fixes
          </Link>
        }
      />
      <div className="ac-toolbar">
        <FilterPanel active={activeFilters(f)} onClear={() => setParams(new URLSearchParams(), { replace: true })}>
          <div className="field">
            <label htmlFor="mw-owner">Assigned to</label>
            <select id="mw-owner" value={f.owner} onChange={(e) => set({ owner: e.target.value as Owner })}>
              {(["mine", "me", "anyone"] as Owner[]).map((o) => (
                <option key={o} value={o}>
                  {OWNER_LABEL[o]}
                </option>
              ))}
            </select>
          </div>
          <ProjectFilter id="mw-project" />
          <div className="field">
            <label htmlFor="mw-prio">Priority</label>
            <select id="mw-prio" value={f.priority} onChange={(e) => set({ priority: e.target.value })}>
              <option value="">Any priority</option>
              {PRIORITIES.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="mw-deadline">Deadline</label>
            <select id="mw-deadline" value={f.deadline} onChange={(e) => set({ deadline: e.target.value as Deadline })}>
              {(["", "overdue", "week"] as Deadline[]).map((d) => (
                <option key={d} value={d}>
                  {DEADLINE_LABEL[d]}
                </option>
              ))}
            </select>
          </div>
        </FilterPanel>
        <p className="small muted mw-scope">
          {OWNER_LABEL[f.owner]}
          {f.priority ? ` · ${f.priority}` : ""}
          {f.deadline ? ` · ${DEADLINE_LABEL[f.deadline]}` : ""}. Assigned to and Deadline apply to issues; Priority to issues and incidents.
        </p>
      </div>
      {sections.map((id) =>
        id === "paid_teaser" ? (
          <ProNotice key={id} feature="remediation">
            With it, automatic fixes waiting for approval and those that failed are listed here too.{" "}
          </ProNotice>
        ) : (
          <SectionFor key={id} id={id} f={f} />
        ),
      )}
    </div>
  );
}

function SectionFor({ id, f }: { id: SectionId; f: MyWorkFilters }) {
  switch (id) {
    case "assigned":
      return <FindingSection id={id} f={f} query={assignedQuery(f, new Date())} />;
    case "overdue":
      return <FindingSection id={id} f={f} query={overdueQuery(f)} />;
    case "approvals":
      return <ApprovalsSection f={f} />;
    case "plans":
      return <PlansSection id={id} f={f} query={{ status: "proposed" }} />;
    case "failed_plans":
      return <PlansSection id={id} f={f} query={failedPlansQuery(new Date())} />;
    case "checks":
      return <ChecksSection f={f} />;
    case "incidents":
      return <IncidentsSection f={f} />;
  }
}

/**
 * One section: its title and count, then up to ROWS rows and a link to the
 * full page; an empty one is a single line.
 */
function Section<T>({
  id,
  f,
  res,
  row,
  hidden,
}: {
  id: SectionId;
  f: MyWorkFilters;
  res: Loaded<List<T>>;
  row: (item: T) => ReactNode;
  /** Leave the section out (the server says this person cannot act on it). */
  hidden?: boolean;
}) {
  if (hidden) return null;
  const title = sectionTitle(id, f);
  const link = fullLink(id, f, new Date());
  const items = res.data?.items ?? [];
  const total = res.data?.total ?? 0;
  if (res.data && total === 0) {
    return (
      <section className="mw-section mw-empty" aria-label={title}>
        <span className="mw-empty-icon" aria-hidden="true">
          <IconCheckCircle size={16} />
        </span>
        <span>{emptyLine(id, f)}</span>
        <Link className="small" to={link}>
          Open the full list
        </Link>
      </section>
    );
  }
  return (
    <section className="mw-section" aria-labelledby={`mw-${id}`}>
      <header className="mw-head">
        <h2 id={`mw-${id}`}>
          {title}
          {res.data && <span className="mw-count">{total.toLocaleString()}</span>}
        </h2>
        <Link className="small" to={link}>
          {total > items.length ? `See all ${total.toLocaleString()}` : "Open the full list"}
        </Link>
      </header>
      <ErrorBox error={res.error} title={`Could not load: ${title.toLowerCase()}`} />
      {!res.data && !res.error && <Loading />}
      {items.length > 0 && <ul className="mw-list">{items.map((it) => row(it))}</ul>}
    </section>
  );
}

/** A row: what it is, a line of detail, and its one action. */
function Row({ lead, title, detail, action }: { lead?: ReactNode; title: ReactNode; detail?: ReactNode; action: { to: string; label: string } }) {
  return (
    <li className="mw-row">
      <span className="mw-lead">{lead}</span>
      <span className="mw-text">
        <span className="mw-title">{title}</span>
        {detail && <span className="small muted">{detail}</span>}
      </span>
      <Link className="btn btn-sm" to={action.to}>
        {action.label}
      </Link>
    </li>
  );
}

function FindingSection({ id, f, query }: { id: SectionId; f: MyWorkFilters; query: Record<string, string> }) {
  const key = JSON.stringify(query);
  const res = useLoad(() => api.get<List<Finding>>("/findings", { ...query, limit: ROWS }), [key]);
  return (
    <Section
      id={id}
      f={f}
      res={res}
      row={(x) => (
        <Row
          key={x.id}
          lead={<PriorityBadge priority={x.priority} />}
          title={x.title || x.key}
          detail={
            <>
              {x.component_name}
              {x.version ? ` ${x.version}` : ""} on {x.asset_name}
              {x.fix_due && (
                <>
                  {" · "}
                  {new Date(x.fix_due).getTime() < Date.now() ? "was due " : "due "}
                  <RelativeTime iso={x.fix_due} />
                </>
              )}
              {f.owner !== "me" && (x.assignee_email || x.assignee_team) ? ` · ${x.assignee_email || x.assignee_team}` : ""}
            </>
          }
          action={{ to: `/findings/${x.id}`, label: "Open" }}
        />
      )}
    />
  );
}

function ApprovalsSection({ f }: { f: MyWorkFilters }) {
  const res = useLoad(() => api.get<IgnoreRequestList>("/ignore-requests", { status: "pending", limit: ROWS }), []);
  return (
    <Section
      id="approvals"
      f={f}
      res={res}
      hidden={res.data ? !res.data.can_decide : false}
      row={(r) => (
        <Row
          key={r.id}
          lead={<Badge status={r.reason} tone="muted" label={IGNORE_REASON_LABEL[r.reason] ?? r.reason} />}
          title={r.title || plural(r.finding_ids.length, "issue")}
          detail={
            <>
              {r.asset_name ? `${r.asset_name} · ` : ""}asked by {r.requested_by || "someone"} <RelativeTime iso={r.requested_at} />
            </>
          }
          action={{ to: "/approvals", label: "Decide" }}
        />
      )}
    />
  );
}

function PlansSection({ id, f, query }: { id: SectionId; f: MyWorkFilters; query: Record<string, string> }) {
  const key = JSON.stringify(query);
  const res = useLoad(() => api.get<List<Plan>>("/remediation/plans", { ...query, limit: ROWS }), [key]);
  return (
    <Section
      id={id}
      f={f}
      res={res}
      row={(p) => {
        const froms = p.from_versions ?? [];
        return (
          <Row
            key={p.id}
            lead={<PlanStatusBadge status={p.status} />}
            title={
              <>
                {p.package} {froms.length === 1 ? froms[0] : froms.length > 1 ? `${froms.length} versions` : ""} → {p.target_version}
              </>
            }
            detail={
              <>
                {plural((p.finding_keys ?? []).length, "issue")} · {p.policy_name || "deleted policy"} · updated <RelativeTime iso={p.updated_at} />
              </>
            }
            action={{ to: `/remediation/plans/${p.id}`, label: id === "plans" ? "Review" : "See what failed" }}
          />
        );
      }}
    />
  );
}

function ChecksSection({ f }: { f: MyWorkFilters }) {
  const res = useLoad(() => api.get<List<Check>>("/checks", { failed: "true", limit: ROWS }), []);
  return (
    <Section
      id="checks"
      f={f}
      res={res}
      row={(c) => (
        <Row
          key={c.id}
          lead={<CheckBadge c={c} />}
          title={c.fix_title || `Whole asset: ${c.asset_name}`}
          detail={
            <>
              {c.fix_title ? `${c.asset_name} · ` : ""}
              {c.remaining > 0 ? `${plural(c.remaining, "issue")} still open · ` : ""}checked <RelativeTime iso={c.completed_at} />
            </>
          }
          action={c.fix_group ? { to: `/fixes/${encodeURIComponent(c.fix_group)}`, label: "Open fix" } : { to: `/assets/${c.asset_id}`, label: "Open asset" }}
        />
      )}
    />
  );
}

function IncidentsSection({ f }: { f: MyWorkFilters }) {
  const query = incidentsQuery(f);
  const key = JSON.stringify(query);
  const res = useLoad(() => api.get<List<Incident>>("/incidents", { ...query, limit: ROWS }), [key]);
  return (
    <Section
      id="incidents"
      f={f}
      res={res}
      row={(i) => (
        <Row
          key={i.id}
          lead={
            <>
              <PriorityBadge priority={i.priority} />
              {i.sos && <Badge status="sos" tone="crit" label="SOS" />}
            </>
          }
          title={i.title}
          detail={
            <>
              {plural(i.finding_count, "issue")} on {plural(i.asset_count, "asset")}
              {i.owner_team ? ` · ${i.owner_team}` : ""} · opened <RelativeTime iso={i.created_at} />
            </>
          }
          action={{ to: `/incidents/${i.id}`, label: "Open" }}
        />
      )}
    />
  );
}
