import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { api, STACK_LAYERS, type Asset, type List, type OwnerPlan, type OwnerRule, type OwnerRuleInput, type Project, type Team, type User } from "../../api";
import { useAction, useLoad } from "../../hooks";
import { plural } from "../../format";
import { AssetSelect } from "../../components/AssetPicker";
import { stackLayerLabel } from "../../components/Stack";
import { Table, type Column } from "../../components/Table";
import { Card, CardFooter, EmptyState, ErrorBox, GoodToKnow, Loading, Notice, PageHeader, SettingRow } from "../../components/ui";
import { OWNER_RULES_EMPTY } from "../../emptyCopy";
import { confirmAction } from "../../components/ConfirmDialog";
import { NoTeamsHint } from "../../components/Teams";
import { ownerLabel } from "../../components/Owners";
import { PlanLimitNote } from "../../components/PlanLimit";

const LEVEL_LABEL: Record<number, string> = {
  6: "Asset, part of its stack",
  5: "Asset",
  4: "Project, part of its stack",
  3: "Project",
  2: "Part of every stack",
  1: "Organisation default",
};

/** People > Owner rules: who new issues are assigned to. */
export function OwnersPage() {
  const rules = useLoad(() => api.get<List<OwnerRule>>("/owner-rules"), []);
  const act = useAction();
  const [editing, setEditing] = useState<number | "new" | null>(null);
  const [plan, setPlan] = useState<OwnerPlan | null>(null);
  const [done, setDone] = useState<string | null>(null);

  const remove = async (r: OwnerRule) => {
    if (
      !(await confirmAction({
        title: "Delete this owner rule?",
        consequence: `${r.describe} → ${ownerLabel(r)}. The ${plural(r.assigned, "open issue")} it assigned keep their owner until you apply the rules again.`,
        action: "Delete rule",
        destructive: true,
      }))
    )
      return;
    const ok = await act.run(() => api.del(`/owner-rules/${r.id}`).then(() => true));
    if (ok) rules.reload();
  };

  const preview = async () => {
    setDone(null);
    const p = await act.run(() => api.post<OwnerPlan>("/owner-rules/apply", { dry_run: true }));
    if (p) setPlan(p);
  };
  const apply = async () => {
    const p = await act.run(() => api.post<OwnerPlan>("/owner-rules/apply", { dry_run: false }));
    if (p) {
      setPlan(null);
      setDone(`${plural(p.total, "open issue")} moved to the owners the rules name.${p.truncated ? " More remain: apply again." : ""}`);
      rules.reload();
    }
  };

  const columns: Column<OwnerRule>[] = [
    { key: "level", header: "Level", cell: (r) => <span className="small">{LEVEL_LABEL[r.level]}</span> },
    {
      key: "what",
      header: "Applies to",
      cell: (r) => (
        <>
          {r.describe}
          {r.note && <div className="muted small">{r.note}</div>}
        </>
      ),
    },
    { key: "owner", header: "Assigned to", cell: (r) => ownerLabel(r) },
    { key: "assigned", header: "Open issues", numeric: true, cell: (r) => r.assigned.toLocaleString() },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (r) => (
        <div className="row-actions">
          <button type="button" className="btn btn-sm" onClick={() => setEditing(editing === r.id ? null : r.id)}>
            Edit
          </button>
          <button type="button" className="btn btn-sm btn-danger" onClick={() => void remove(r)}>
            Delete
          </button>
        </div>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        help="owner-rules"
        title="Owner rules"
        sub="Who new issues are assigned to, so each one lands with the person or team that can fix it. Issues a person assigned by hand are never changed."
        actions={
          <>
            <button type="button" className="btn" onClick={() => void preview()} disabled={act.pending}>
              Apply to open issues…
            </button>
            <button type="button" className="btn btn-primary" onClick={() => setEditing(editing === "new" ? null : "new")}>
              Add rule
            </button>
          </>
        }
      />
      <PlanLimitNote kind="owner_rules" />
      <ErrorBox error={act.error} title="Could not save" />
      {done && <Notice kind="success">{done}</Notice>}
      {editing === "new" && (
        <RuleForm
          onSaved={() => {
            setEditing(null);
            rules.reload();
          }}
          onCancel={() => setEditing(null)}
        />
      )}
      {plan && (
        <Card title="Apply the rules to open issues" description="A preview: nothing moves until you confirm.">
          {plan.total === 0 ? (
            <p>Every open issue is already with the owner the rules name. Nothing to move.</p>
          ) : (
            <>
              <p>
                {plural(plan.total, "open issue")} would move. Issues a person assigned stay as they are.
                {plan.truncated && " This is the first 20,000; apply again for the rest."}
              </p>
              <ul className="ref-list small">
                {plan.moves.map((m, i) => (
                  <li key={i}>
                    <strong>{m.count.toLocaleString()}</strong> from {[m.from_user, m.from_team && `team ${m.from_team}`].filter(Boolean).join(" and ") || "nobody"}{" "}
                    to {[m.to_user, m.to_team && `team ${m.to_team}`].filter(Boolean).join(" and ") || "nobody (no rule matches any more)"}
                    {m.rule && <span className="muted"> · rule: {m.rule}</span>} ·{" "}
                    {m.finding_ids.slice(0, 3).map((id, j) => (
                      <span key={id}>
                        {j > 0 && ", "}
                        <Link to={`/findings/${id}`}>#{id}</Link>
                      </span>
                    ))}
                  </li>
                ))}
              </ul>
            </>
          )}
          <CardFooter>
            <button type="button" className="btn" onClick={() => setPlan(null)}>
              Close
            </button>
            {plan.total > 0 && (
              <button type="button" className="btn btn-primary" onClick={() => void apply()} disabled={act.pending}>
                Move {plural(plan.total, "issue")}
              </button>
            )}
          </CardFooter>
        </Card>
      )}
      <ErrorBox error={rules.error} title="Could not load owner rules" />
      {!rules.data && !rules.error && <Loading />}
      {rules.data && rules.data.items.length === 0 && editing !== "new" && (
        <EmptyState {...OWNER_RULES_EMPTY} action={{ ...OWNER_RULES_EMPTY.action!, onClick: () => setEditing("new") }} help="owner-rules">
          <p>
            A rule is, for example, “operating system packages on every server → the infra team” or “everything in the Shop project → Anita”.
          </p>
        </EmptyState>
      )}
      {rules.data && rules.data.items.length > 0 && (
        <Table
          caption="Owner rules"
          columns={columns}
          rows={rules.data.items}
          rowKey={(r) => r.id}
          selectedKey={typeof editing === "number" ? editing : null}
          renderExpanded={(r) => (
            <RuleForm
              rule={r}
              onSaved={() => {
                setEditing(null);
                rules.reload();
              }}
              onCancel={() => setEditing(null)}
            />
          )}
        />
      )}
      {rules.data && rules.data.items.length > 0 && (
        <GoodToKnow title="Which rule wins">
          <p>
            When several rules match an issue, the most specific one assigns it: a rule for part of an asset&apos;s stack, then the asset, part of a
            project&apos;s stack, the project, part of every stack, and last the organisation default (the Level column).
          </p>
        </GoodToKnow>
      )}
    </>
  );
}

type Scope = "organisation" | "project" | "asset";

function RuleForm({ rule, onSaved, onCancel }: { rule?: OwnerRule; onSaved: () => void; onCancel: () => void }) {
  const projects = useLoad(() => api.get<List<Project>>("/projects"), []);
  const assets = useLoad(() => api.get<List<Asset>>("/assets", { limit: 200 }), []);
  const users = useLoad(() => api.get<List<User>>("/users"), []);
  const teams = useLoad(() => api.get<List<Team>>("/teams"), []);
  const act = useAction();
  const [scope, setScope] = useState<Scope>(rule?.asset_id ? "asset" : rule?.project_id ? "project" : "organisation");
  const [projectId, setProjectId] = useState(rule?.project_id ? String(rule.project_id) : "");
  const [assetId, setAssetId] = useState(rule?.asset_id ? String(rule.asset_id) : "");
  const [layer, setLayer] = useState(rule?.layer ?? "");
  const [component, setComponent] = useState(rule?.component ?? "");
  const [userId, setUserId] = useState(rule?.user_id ? String(rule.user_id) : "");
  const [teamId, setTeamId] = useState(rule?.team_id ? String(rule.team_id) : "");
  const [note, setNote] = useState(rule?.note ?? "");
  const p = rule ? `or-${rule.id}` : "or-new";

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const body: OwnerRuleInput = {
      project_id: scope === "project" && projectId ? Number(projectId) : null,
      asset_id: scope === "asset" && assetId ? Number(assetId) : null,
      layer,
      component: component.trim(),
      user_id: userId ? Number(userId) : null,
      team_id: teamId ? Number(teamId) : null,
      note: note.trim(),
    };
    const ok = await act.run(() => (rule ? api.put(`/owner-rules/${rule.id}`, body) : api.post("/owner-rules", body)).then(() => true));
    if (ok) onSaved();
  };
  const missingScope = (scope === "project" && !projectId) || (scope === "asset" && !assetId);
  const people = (users.data?.items ?? []).filter((u) => u.role || u.access === "projects");

  return (
    <Card
      title={rule ? "Edit owner rule" : "New owner rule"}
      description="Which issues this rule covers, and who gets them. New issues get their owner within a minute."
    >
      <form className="form" onSubmit={(e) => void submit(e)}>
        <ErrorBox error={act.error} title="Could not save the rule" />
        <SettingRow title="Where" description="Every asset, the assets of one project, or a single asset.">
          <div className="form-grid">
            <div className="field">
              <label htmlFor={`${p}-scope`}>Where</label>
              <select id={`${p}-scope`} value={scope} onChange={(e) => setScope(e.target.value as Scope)}>
                <option value="organisation">Every asset</option>
                <option value="project">One project</option>
                <option value="asset">One asset</option>
              </select>
            </div>
            {scope === "project" && (
              <div className="field">
                <label htmlFor={`${p}-project`}>Project</label>
                <select id={`${p}-project`} value={projectId} onChange={(e) => setProjectId(e.target.value)} required>
                  <option value="">Choose a project</option>
                  {projects.data?.items.map((x) => (
                    <option key={x.id} value={String(x.id)}>
                      {x.name}
                    </option>
                  ))}
                </select>
                {projects.data && projects.data.items.length === 0 && (
                  <p className="hint">
                    No projects yet. <Link to="/projects">Create one</Link>.
                  </p>
                )}
              </div>
            )}
            {scope === "asset" && (
              <div className="field">
                <label htmlFor={`${p}-asset`}>Asset</label>
                <AssetSelect id={`${p}-asset`} value={assetId} onChange={setAssetId} assets={assets.data?.items} allLabel="Choose an asset" />
              </div>
            )}
          </div>
        </SettingRow>
        <SettingRow
          title="Which part of the stack (optional)"
          description="Narrow the rule to one layer, such as the operating system or the web server, or to packages by name. Leave both empty for everything."
        >
          <div className="form-grid">
            <div className="field">
              <label htmlFor={`${p}-layer`}>Part of the stack</label>
              <select id={`${p}-layer`} value={layer} onChange={(e) => setLayer(e.target.value)}>
                <option value="">Any layer</option>
                {STACK_LAYERS.map((l) => (
                  <option key={l} value={l}>
                    {stackLayerLabel(l)}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor={`${p}-component`}>Package name</label>
              <input
                id={`${p}-component`}
                maxLength={200}
                value={component}
                onChange={(e) => setComponent(e.target.value)}
                placeholder="Any package, or e.g. openssl, linux*, wordpress"
              />
            </div>
          </div>
          <p className="hint">Package names match the whole name, ignoring case; * matches anything.</p>
        </SettingRow>
        <SettingRow title="Who" description="The person, the team, or both, that matching issues are assigned to. Choose at least one.">
          <div className="form-grid">
            <div className="field">
              <label htmlFor={`${p}-user`}>Person</label>
              <select id={`${p}-user`} value={userId} onChange={(e) => setUserId(e.target.value)}>
                <option value="">No one in particular</option>
                {people.map((u) => (
                  <option key={u.id} value={String(u.id)}>
                    {u.name ? `${u.name} (${u.email})` : u.email}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor={`${p}-team`}>Team</label>
              <select id={`${p}-team`} value={teamId} onChange={(e) => setTeamId(e.target.value)}>
                <option value="">No team</option>
                {teams.data?.items.map((t) => (
                  <option key={t.id} value={String(t.id)}>
                    {t.name}
                  </option>
                ))}
              </select>
              {teams.data && teams.data.items.length === 0 && <NoTeamsHint what="assign issues to a team" />}
            </div>
            <div className="field">
              <label htmlFor={`${p}-note`}>Note (optional)</label>
              <input id={`${p}-note`} maxLength={500} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Why this owner" />
            </div>
          </div>
        </SettingRow>
        <CardFooter status="Issues a rule already assigned move only when you apply the rules (Apply to open issues).">
          <button type="button" className="btn" onClick={onCancel}>
            Cancel
          </button>
          <button type="submit" className="btn btn-primary" disabled={act.pending || missingScope || (!userId && !teamId)}>
            {rule ? "Save rule" : "Add rule"}
          </button>
        </CardFooter>
      </form>
    </Card>
  );
}
