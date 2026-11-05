import { useState, type FormEvent } from "react";
import { api, atLeast, USER_ROLES, type List, type Role, type Token, type UserRole } from "../../api";
import { PERMISSIONS, ROLE_HELP } from "../../roles";
import { useAuth } from "../../auth";
import { useAction, useLoad } from "../../hooks";
import { Badge } from "../../components/Badge";
import { Table, type Column } from "../../components/Table";
import {
  Card,
  CardFooter,
  ChoiceCards,
  Code,
  CopyBox,
  EmptyState,
  ErrorBox,
  Loading,
  PageHeader,
  RelativeTime,
  SettingRow,
  type ChoiceOption,
} from "../../components/ui";
import { tokensEmpty } from "../../emptyCopy";
import { confirmAction } from "../../components/ConfirmDialog";
import { PlanLimitNote } from "../../components/PlanLimit";

function tokenState(t: Token): string {
  if (t.revoked_at) return "revoked";
  if (t.expires_at && new Date(t.expires_at).getTime() < Date.now()) return "expired";
  return "active";
}

export function TokensPage() {
  const { me, can } = useAuth();
  const admin = can("admin");
  const res = useLoad(() => api.get<List<Token>>("/tokens"), []);
  const act = useAction();
  const [created, setCreated] = useState<{ token: Token; secret: string } | null>(null);
  const [showRevoked, setShowRevoked] = useState(false);

  const revoke = async (t: Token) => {
    if (
      !(await confirmAction({
        title: `Revoke token "${t.name}" (${t.prefix}…)?`,
        consequence: "Anything using it stops working immediately.",
        action: "Revoke token",
        destructive: true,
        typeToConfirm: t.name,
      }))
    )
      return;
    const ok = await act.run(() => api.del(`/tokens/${t.id}`).then(() => true));
    if (ok) res.reload();
  };

  const rows = (res.data?.items ?? []).filter((t) => showRevoked || !t.revoked_at);

  const columns: Column<Token>[] = [
    { key: "name", header: "Name", cell: (t) => t.name },
    { key: "prefix", header: "Prefix", cell: (t) => <span className="mono">{t.prefix}…</span> },
    { key: "role", header: "Role", cell: (t) => <span className={`role-pill role-${t.role}`}>{t.role}</span> },
  ];
  if (admin)
    columns.push({
      key: "owner",
      header: "Owner",
      cell: (t) =>
        t.user_id === null ? <span className="muted">collector (no user)</span> : t.user_id === me?.user?.id ? "you" : t.user_email || `user #${t.user_id}`,
    });
  columns.push(
    { key: "state", header: "Status", cell: (t) => <Badge status={tokenState(t)} /> },
    { key: "created", header: "Created", cell: (t) => <RelativeTime iso={t.created_at} /> },
    { key: "expires", header: "Expires", cell: (t) => <RelativeTime iso={t.expires_at} empty="never" /> },
    { key: "used", header: "Last used", cell: (t) => <RelativeTime iso={t.last_used_at} /> },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (t) =>
        !t.revoked_at && (
          <button type="button" className="btn btn-sm btn-link-danger" onClick={() => revoke(t)} disabled={act.pending}>
            Revoke
          </button>
        ),
    },
  );

  return (
    <>
      <PageHeader help="api-tokens"
        title="API tokens"
        sub={
          admin
            ? "Tokens for scripts, CI and collectors. As an admin you see every token."
            : "Personal tokens for scripts and CI. A token can never have more rights than you."
        }
      />
      <PlanLimitNote kind="api_tokens" />
      {created && (
        <div className="alert alert-warn secret-reveal" role="alert">
          <p>
            <strong>Copy this token now.</strong> It is shown only once and cannot be recovered. Store it in a secret
            manager; if it is lost, revoke it and create another.
          </p>
          <CopyBox value={created.secret} label={`Secret for token ${created.token.name}`} />
          <p className="small">
            Use it as <Code>Authorization: Bearer {created.token.prefix}…</Code>
            {created.token.role === "collector" && (
              <>
                {" "}
                or <Code>STACKURITY_TOKEN</Code> for <Code>stackurity agent</Code> / <Code>stackurity scan</Code>
              </>
            )}
            .
          </p>
          <button type="button" className="btn btn-sm" onClick={() => setCreated(null)}>
            I have stored it
          </button>
        </div>
      )}
      {me?.user && me.token === null && (
        <CreateToken
          role={highest(me.role, me.project_role)}
          admin={admin}
          onCreated={(c) => {
            setCreated(c);
            res.reload();
          }}
        />
      )}
      <ErrorBox error={act.error} title="Revoke failed" />
      <div className="filters">
        <label className="check">
          <input type="checkbox" checked={showRevoked} onChange={(e) => setShowRevoked(e.target.checked)} /> Show revoked
        </label>
      </div>
      <ErrorBox error={res.error} title="Could not load tokens" />
      {!res.data && !res.error && <Loading />}
      {res.data && rows.length === 0 && <EmptyState {...tokensEmpty(res.data.items.length > 0, Boolean(me?.user && me.token === null))} />}
      {rows.length > 0 && <Table caption="API tokens" columns={columns} rows={rows} rowKey={(t) => t.id} rowClassName={(t) => (t.revoked_at ? "row-removed" : undefined)} />}
    </>
  );
}

/** The higher of the organisation role and the project role: a token never acts above it, and the server checks each asset. */
function highest(org: Role | "", project: Role | "" | undefined): Role {
  if (org && project) return atLeast(org, project as Exclude<Role, "collector">) ? org : project;
  return (org || project || "viewer") as Role;
}

function CreateToken({ role, admin, onCreated }: { role: Role; admin: boolean; onCreated: (c: { token: Token; secret: string }) => void }) {
  const roles: Role[] = USER_ROLES.filter((r) => atLeast(role, r));
  if (admin) roles.unshift("collector");
  const [name, setName] = useState("");
  const [r, setR] = useState<Role>(admin ? "collector" : "viewer");
  const [ttl, setTtl] = useState("");
  const act = useAction();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ttlHours = ttl ? Number(ttl) : 0;
    const c = await act.run(() => api.post<{ token: Token; secret: string }>("/tokens", { name: name.trim(), role: r, ttl_hours: ttlHours }));
    if (c) {
      setName("");
      setTtl("");
      onCreated(c);
    }
  };

  const options: ChoiceOption<Role>[] = roles.map((x) =>
    x === "collector"
      ? {
          value: x,
          label: "collector (submit observations only)",
          description: "For servers, CI pipelines and scanners that send what they find. It cannot read anything back.",
        }
      : { value: x, label: PERMISSIONS.find((p) => p.role === x)?.label ?? x, description: ROLE_HELP[x as UserRole] },
  );

  return (
    <Card
      title="Create token"
      description="A token lets a script, CI pipeline or server talk to Stackurity without signing in. Create one per use, so you can revoke it on its own."
    >
      <form className="form" onSubmit={submit}>
        <ErrorBox error={act.error} title="Could not create token" />
        <SettingRow title="Name" description="Where it will be used, so you recognise it in the list later.">
          <div className="field">
            <label className="sr-only" htmlFor="tk-name">
              Name
            </label>
            <input id="tk-name" required maxLength={100} placeholder="e.g. github-actions" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
        </SettingRow>
        <SettingRow title="Role" description="What the token may do. Give it the least it needs; it can never do more than you.">
          <ChoiceCards name="tk-role" legend="Role" options={options} value={r} onChange={setR} />
        </SettingRow>
        <SettingRow title="Expires after (hours)" description="A token that expires is safer if it leaks. Leave empty for no expiry.">
          <div className="field">
            <label className="sr-only" htmlFor="tk-ttl">
              Expires after (hours)
            </label>
            <input id="tk-ttl" type="number" min={1} max={8784} placeholder="never" value={ttl} onChange={(e) => setTtl(e.target.value)} />
            <p className="hint">Maximum 8784 (one year). For example, 720 is 30 days.</p>
          </div>
        </SettingRow>
        <CardFooter status="The token is shown once, right after you create it.">
          <button type="submit" className="btn btn-primary" disabled={act.pending || !name.trim()}>
            Create token
          </button>
        </CardFooter>
      </form>
    </Card>
  );
}
