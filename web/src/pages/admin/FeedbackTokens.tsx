import { useState, type FormEvent } from "react";
import { api } from "../../api";
import { useAction, useLoad } from "../../hooks";
import { Badge } from "../../components/Badge";
import { Table, type Column } from "../../components/Table";
import { TableSkeleton } from "../../components/Skeleton";
import { Card, CardFooter, ChoiceCards, Code, CopyBox, EmptyState, ErrorBox, RelativeTime, SettingRow } from "../../components/ui";
import { confirmAction } from "../../components/ConfirmDialog";
import { FEEDBACK_TOKEN_SCOPES, feedbackTokenState, type FeedbackToken } from "../../feedbackTokens";

const STATE_LABEL: Record<string, string> = { revoked: "Revoked", expired: "Expired", expiring: "Expires soon", active: "Active" };
const STATE_TONE: Record<string, "good" | "warn" | "bad" | "muted"> = { revoked: "muted", expired: "bad", expiring: "warn", active: "good" };

type Created = { token: string; info: FeedbackToken };

/**
 * Admin → Feedback → Agent tokens: create, list and revoke the tokens the
 * feedback agent and the virus scanner use (POST/GET/DELETE
 * /admin/feedback-tokens, instance administrators only). The secret is
 * shown once.
 */
export function FeedbackTokens() {
  const res = useLoad(() => api.get<{ tokens: FeedbackToken[] }>("/admin/feedback-tokens"), []);
  const act = useAction();
  const [created, setCreated] = useState<Created | null>(null);
  const [showOld, setShowOld] = useState(false);

  const revoke = async (t: FeedbackToken) => {
    if (
      !(await confirmAction({
        title: `Revoke token "${t.name}" (${t.prefix}…)?`,
        consequence: t.scope === "triage" ? "The feedback agent stops working on the queue until it gets a new token." : "The virus scan stops until it gets a new token.",
        action: "Revoke token",
        destructive: true,
      }))
    )
      return;
    const ok = await act.run(() => api.del(`/admin/feedback-tokens/${t.id}`).then(() => true));
    if (ok) res.reload();
  };

  const all = res.data?.tokens ?? [];
  const rows = all.filter((t) => showOld || (!t.revoked_at && new Date(t.expires_at).getTime() > Date.now()));
  const columns: Column<FeedbackToken>[] = [
    { key: "name", header: "Name", cell: (t) => t.name },
    { key: "scope", header: "Used by", cell: (t) => FEEDBACK_TOKEN_SCOPES.find((s) => s.id === t.scope)?.label ?? t.scope },
    { key: "prefix", header: "Prefix", cell: (t) => <span className="mono">{t.prefix}…</span> },
    {
      key: "state",
      header: "Status",
      cell: (t) => {
        const s = feedbackTokenState(t);
        return <Badge status={s} tone={STATE_TONE[s]} label={STATE_LABEL[s]} />;
      },
    },
    { key: "expires", header: "Expires", cell: (t) => <RelativeTime iso={t.expires_at} /> },
    { key: "used", header: "Last used", cell: (t) => <RelativeTime iso={t.last_used_at} empty="never" /> },
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
  ];
  const scope = created ? FEEDBACK_TOKEN_SCOPES.find((s) => s.id === created.info.scope) : undefined;

  return (
    <>
      <Card
        id="agent-tokens"
        title="Agent tokens"
        description="The feedback agent and the virus scanner sign in with these. They only reach the feedback queue, never a workspace, and last 90 days at most."
      >
        {created && (
          <div className="alert alert-warn secret-reveal" role="alert">
            <p>
              <strong>Copy this token now.</strong> It is shown only once. If it is lost, revoke it and create another.
            </p>
            <CopyBox value={created.token} label={`Secret for token ${created.info.name}`} />
            <p className="small">
              {created.info.scope === "triage" ? (
                <>
                  Then, on the Mac, run <Code>pbpaste &gt; ~/.config/stackurity/feedback-agent-token &amp;&amp; chmod 600 ~/.config/stackurity/feedback-agent-token</Code>.
                  The agent picks it up on its next run, within ten minutes.
                </>
              ) : (
                <>Save it with mode 0600 in {scope ? scope.file : "its token file"}.</>
              )}
            </p>
            <button type="button" className="btn btn-sm" onClick={() => setCreated(null)}>
              I have stored it
            </button>
          </div>
        )}
        <ErrorBox error={act.error} title="Revoke failed" />
        <ErrorBox error={res.error} title="Could not load agent tokens" />
        {!res.data && !res.error && <TableSkeleton label="Loading agent tokens…" />}
        {res.data && all.length > 0 && (
          <div className="filters">
            <label className="check">
              <input type="checkbox" checked={showOld} onChange={(e) => setShowOld(e.target.checked)} /> Show revoked and expired
            </label>
          </div>
        )}
        {res.data && rows.length === 0 && (
          <EmptyState title={all.length === 0 ? "No agent tokens yet." : "No active agent tokens."}>
            The feedback agent needs a token before it can work on the queue. Create one below.
          </EmptyState>
        )}
        {rows.length > 0 && (
          <Table caption="Agent tokens" columns={columns} rows={rows} rowKey={(t) => t.id} rowClassName={(t) => (t.revoked_at ? "row-removed" : undefined)} />
        )}
      </Card>
      <CreateFeedbackToken
        onCreated={(c) => {
          setCreated(c);
          res.reload();
          document.getElementById("agent-tokens")?.scrollIntoView({ behavior: "smooth", block: "start" });
        }}
      />
    </>
  );
}

function CreateFeedbackToken({ onCreated }: { onCreated: (c: Created) => void }) {
  const [name, setName] = useState("feedback-agent");
  const [scope, setScope] = useState<FeedbackToken["scope"]>("triage");
  const [days, setDays] = useState(90);
  const act = useAction();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const c = await act.run(() => api.post<Created>("/admin/feedback-tokens", { name: name.trim(), scope, days }));
    if (c) onCreated(c);
  };
  return (
    <Card title="Create an agent token" description="Make one token per program that signs in, so you can revoke it on its own.">
      <form className="form" onSubmit={submit}>
        <ErrorBox error={act.error} title="Could not create the token" />
        <SettingRow title="Name" description="So you recognise it in the list later.">
          <div className="field">
            <label className="sr-only" htmlFor="fbt-name">
              Name
            </label>
            <input id="fbt-name" required maxLength={100} placeholder="e.g. feedback-agent" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
        </SettingRow>
        <SettingRow title="Used by" description="What the token may do. Each one reaches only its own part of the queue.">
          <ChoiceCards
            name="fbt-scope"
            legend="Used by"
            columns={2}
            options={FEEDBACK_TOKEN_SCOPES.map((s) => ({ value: s.id, label: s.label, description: s.help }))}
            value={scope}
            onChange={setScope}
          />
        </SettingRow>
        <SettingRow title="Expires after" description="90 days is the longest allowed. The list warns two weeks before it runs out.">
          <div className="field">
            <label className="sr-only" htmlFor="fbt-days">
              Expires after
            </label>
            <select id="fbt-days" value={days} onChange={(e) => setDays(Number(e.target.value))}>
              <option value={30}>30 days</option>
              <option value={60}>60 days</option>
              <option value={90}>90 days</option>
            </select>
          </div>
        </SettingRow>
        <CardFooter status="The token is shown once, right after you create it.">
          <button type="submit" className="btn btn-primary" disabled={act.pending || !name.trim()}>
            {act.pending ? "Creating…" : "Create token"}
          </button>
        </CardFooter>
      </form>
    </Card>
  );
}
