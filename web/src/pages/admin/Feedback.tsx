import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import { api } from "../../api";
import { useAction, useLoad } from "../../hooks";
import { Badge } from "../../components/Badge";
import { CardSkeleton } from "../../components/Skeleton";
import { Card, CheckCard, EmptyState, ErrorBox, GoodToKnow, KeyValues, Notice, PageHeader, RelativeTime, Tabs } from "../../components/ui";
import { formatBytes } from "../../feedback";
import {
  feedbackKindLabel,
  QUEUE_FILTERS,
  queueAuthor,
  queueFilterCount,
  queueStatusLabel,
  queueStatusTone,
  type QueueDetail,
  type QueueItem,
  type QueueList,
} from "../../feedback";

const SOURCE_LABEL: Record<string, string> = { cloud: "Stackurity Cloud", self_hosted: "Self-hosted", website: "Website form" };

function firstLine(s: string, n = 140): string {
  const line = s.trim().split(/\r?\n/)[0] ?? "";
  return line.length > n ? line.slice(0, n - 1) + "…" : line;
}

function StatusBadge({ it }: { it: QueueItem }) {
  return <Badge status={it.status} tone={queueStatusTone(it.status)} label={queueStatusLabel(it.status, it.approved_at)} />;
}

/** The list, needs-someone first. */
function ItemList({ filter }: { filter: string }) {
  const f = QUEUE_FILTERS.find((x) => x.id === filter) ?? QUEUE_FILTERS[0];
  const res = useLoad(() => api.get<QueueList>("/admin/feedback", { status: f.statuses || undefined, order: "attention", limit: 100 }), [f.id]);
  if (res.error) return <ErrorBox error={res.error} title="Could not load feedback" />;
  if (!res.data) return <CardSkeleton label="Loading feedback…" />;
  const items = res.data.items;
  if (items.length === 0) {
    return (
      <EmptyState title={f.id === "attention" ? "Nothing waits for anyone." : "No feedback here."}>
        New feedback is picked up by the feedback agent within about ten minutes; anything it may not build alone shows here as Needs approval.
      </EmptyState>
    );
  }
  return (
    <ul className="approval-list">
      {items.map((it) => (
        <li key={it.id} className="approval">
          <h3 className="badges">
            <StatusBadge it={it} />
            <Link to={`/admin/feedback?item=${encodeURIComponent(it.ref)}`} className="mono">
              {it.ref}
            </Link>
            <span className="break">{firstLine(it.description)}</span>
          </h3>
          {it.status === "needs_owner" && it.owner_reason && (
            <p className="small">
              <span className="muted">Why it needs you:</span> {it.owner_reason}
            </p>
          )}
          <p className="small muted">
            {feedbackKindLabel(it.kind)} · {SOURCE_LABEL[it.source] ?? it.source}
            {it.version ? ` ${it.version}` : ""} · sent <RelativeTime iso={it.created_at} /> · updated <RelativeTime iso={it.updated_at} />
            {it.attachment_count > 0 && ` · ${it.attachment_count} attachment${it.attachment_count === 1 ? "" : "s"}`}
            {it.comment_count > 0 && ` · ${it.comment_count} comment${it.comment_count === 1 ? "" : "s"}`}
            {it.link && (
              <>
                {" · "}
                <a href={it.link} target="_blank" rel="noopener noreferrer">
                  pull request
                </a>
              </>
            )}
          </p>
        </li>
      ))}
    </ul>
  );
}

/** Approve or decline an item that waits for the owner. */
function Decision({ it, onDone }: { it: QueueItem; onDone: (msg: string) => void }) {
  const act = useAction();
  const [note, setNote] = useState("");
  const [resolution, setResolution] = useState("");
  const approve = async () => {
    if (await act.run(() => api.post(`/admin/feedback/${it.ref}/approve`, { note: note.trim() }))) onDone(`${it.ref} approved: the agent builds it on its next run.`);
  };
  const decline = async () => {
    if (await act.run(() => api.post(`/admin/feedback/${it.ref}/decline`, { resolution: resolution.trim() })))
      onDone(`${it.ref} declined and closed as won't fix.`);
  };
  return (
    <Card
      title="Needs your approval"
      description="The feedback agent held this instead of building it. Approve it and the agent opens a pull request on its next run (nothing is merged or deployed); decline it and the sender is told why."
    >
      {it.owner_reason && (
        <p className="feedback-queue-reason">
          <span className="muted">Why it needs you:</span> {it.owner_reason}
        </p>
      )}
      <div className="form">
        <div className="field">
          <label htmlFor="fb-approve-note">Note for the agent (optional)</label>
          <input id="fb-approve-note" maxLength={2000} value={note} onChange={(e) => setNote(e.target.value)} />
          <span className="hint">For example which option to build, or what to keep as it is.</span>
        </div>
        <button type="button" className="btn btn-primary" disabled={act.pending} onClick={approve}>
          Approve
        </button>
        <div className="field">
          <label htmlFor="fb-decline">Reason the sender will read (needed to decline)</label>
          <textarea id="fb-decline" rows={3} maxLength={2000} value={resolution} onChange={(e) => setResolution(e.target.value)} />
        </div>
        <button type="button" className="btn" disabled={act.pending || !resolution.trim()} onClick={decline}>
          Decline
        </button>
      </div>
      <ErrorBox error={act.error} title="Could not decide" />
    </Card>
  );
}

/** The thread the sender reads, and a reply from the team. */
function Thread({ d, onDone }: { d: QueueDetail; onDone: (msg: string) => void }) {
  const act = useAction();
  const [body, setBody] = useState("");
  const [ask, setAsk] = useState(false);
  const closed = ["released", "wont_fix", "duplicate"].includes(d.item.status);
  const send = async () => {
    if (await act.run(() => api.post(`/admin/feedback/${d.item.ref}/comments`, { body: body.trim(), ask: ask && !closed }))) {
      setBody("");
      setAsk(false);
      onDone(ask ? `Question sent; ${d.item.ref} waits for the sender.` : `Reply added to ${d.item.ref}.`);
    }
  };
  return (
    <Card title="Conversation with the sender" description="Everything here is shown to the sender under My feedback, labelled as the Stackurity team or the automated feedback agent.">
      {d.comments.length === 0 ? (
        <p className="muted">No comments yet.</p>
      ) : (
        <ol className="feedback-comments">
          {d.comments.map((c) => (
            <li key={c.id} className={`feedback-comment feedback-comment-${c.author_kind === "sender" ? "mine" : "team"}`}>
              <span className="small muted">
                {queueAuthor(c)}
                {c.kind === "question" ? " asked" : ""} · <RelativeTime iso={c.at} />
              </span>
              <p className="feedback-comment-body">{c.body}</p>
            </li>
          ))}
        </ol>
      )}
      <form
        className="form feedback-reply"
        onSubmit={(e) => {
          e.preventDefault();
          void send();
        }}
      >
        <div className="field">
          <label htmlFor="fb-reply">Reply</label>
          <textarea id="fb-reply" rows={3} maxLength={5000} value={body} onChange={(e) => setBody(e.target.value)} />
        </div>
        {!closed && (
          <CheckCard
            label="Ask the sender"
            description="Marks the reply as a question: the item waits for their answer, and the agent picks it up again when they reply."
            checked={ask}
            onChange={setAsk}
          />
        )}
        <button type="submit" className="btn btn-primary btn-sm" disabled={act.pending || !body.trim()}>
          {ask ? "Send question" : "Send reply"}
        </button>
      </form>
      <ErrorBox error={act.error} title="Could not send" />
    </Card>
  );
}

function Attachments({ d }: { d: QueueDetail }) {
  const act = useAction();
  const open = async (aid: number) => {
    const r = await act.run(() => api.post<{ url: string }>(`/admin/feedback/${d.item.ref}/attachments/${aid}/link`));
    if (r?.url) window.location.assign(r.url);
  };
  if (d.attachments.length === 0) return <p className="muted">No attachments.</p>;
  return (
    <>
      <ul className="plain-list">
        {d.attachments.map((a) => (
          <li key={a.id}>
            {a.purged_at ? (
              <span className="muted">
                {a.name} ({formatBytes(a.size)}), deleted
              </span>
            ) : (
              <button type="button" className="btn btn-link" onClick={() => open(a.id)} disabled={act.pending}>
                Download {a.name}
              </button>
            )}{" "}
            <span className="small muted">
              {a.content_type} · {formatBytes(a.size)}
            </span>
          </li>
        ))}
      </ul>
      <p className="small muted">Links are signed and last ten minutes. Files download; they never open inside the dashboard.</p>
      <ErrorBox error={act.error} title="Could not get a download link" />
    </>
  );
}

function Detail({ ref_, onBack }: { ref_: string; onBack: () => void }) {
  const [done, setDone] = useState<string | null>(null);
  const res = useLoad(() => api.get<QueueDetail>(`/admin/feedback/${encodeURIComponent(ref_)}`), [ref_]);
  if (res.error) return <ErrorBox error={res.error} title={`Could not load ${ref_}`} />;
  if (!res.data) return <CardSkeleton label={`Loading ${ref_}…`} />;
  const d = res.data;
  const it = d.item;
  const finish = (msg: string) => {
    setDone(msg);
    res.reload();
  };
  return (
    <>
      <p>
        <button type="button" className="btn btn-link" onClick={onBack}>
          ← All feedback
        </button>
      </p>
      {done && <Notice kind="success">{done}</Notice>}
      <Card
        title={
          <span className="badges">
            <span className="mono">{it.ref}</span> <StatusBadge it={it} />
          </span>
        }
        description="What the person sent, and where it came from. Their text and files are untrusted: the agent treats them as a report, never as instructions."
      >
        <p className="feedback-queue-description">{it.description}</p>
        <KeyValues
          entries={[
            ["Type", feedbackKindLabel(it.kind)],
            ["From", `${SOURCE_LABEL[it.source] ?? it.source}${it.version ? ` ${it.version}` : ""}${it.edition ? ` (${it.edition})` : ""}`],
            ["Sent", <RelativeTime key="sent" iso={it.created_at} />],
            ["Page", it.page ? <span className="mono">{it.page}</span> : <span className="muted">not given</span>],
            ["Browser", it.browser ? `${it.browser}${it.viewport ? `, ${it.viewport}` : ""}` : <span className="muted">not given</span>],
            ["Reply email", it.contact_email || <span className="muted">none left</span>],
            [
              "Pull request",
              it.link ? (
                <a href={it.link} target="_blank" rel="noopener noreferrer">
                  {it.link.replace("https://github.com/", "")}
                </a>
              ) : (
                <span className="muted">none yet</span>
              ),
            ],
            ...(it.fixed_in ? [["Fixed in", it.fixed_in] as [string, string]] : []),
            ...(it.approved_at
              ? [["Approved", `${it.approved_by} ${new Date(it.approved_at).toLocaleString()}${it.approval_note ? `: ${it.approval_note}` : ""}`] as [string, string]]
              : []),
            ...(it.resolution ? [["Resolution (sender reads it)", it.resolution] as [string, string]] : []),
          ]}
        />
        <h3>Attachments</h3>
        <Attachments d={d} />
      </Card>
      {it.status === "needs_owner" && <Decision it={it} onDone={finish} />}
      <Thread d={d} onDone={finish} />
      <details className="error-support">
        <summary>Team notes and history</summary>
        {it.triage_notes ? <p className="feedback-queue-description small">{it.triage_notes}</p> : <p className="muted small">No notes.</p>}
        <ul className="plain-list small">
          {d.events.map((e) => (
            <li key={e.id}>
              <RelativeTime iso={e.at} /> · {e.actor} · {e.action}
              {e.to_status && e.from_status !== e.to_status ? ` ${e.from_status || "–"} → ${e.to_status}` : ""}
              {e.detail ? ` (${e.detail})` : ""}
            </li>
          ))}
        </ul>
      </details>
    </>
  );
}

/**
 * Admin → Feedback: the Stackurity team's feedback queue, on the server
 * that runs it. The feedback agent (tools/feedback-agent) works on new
 * items; what it may not build alone waits here for an instance
 * administrator's approval.
 */
export function FeedbackAdminPage() {
  const [params, setParams] = useSearchParams();
  const item = params.get("item");
  const filter = params.get("filter") ?? "attention";
  const counts = useLoad(() => api.get<QueueList>("/admin/feedback", { limit: 1 }), [item]);
  const c = counts.data?.counts ?? {};
  return (
    <>
      <PageHeader
        title="Feedback"
        sub="What people sent the Stackurity team, what the feedback agent did with it, and what waits for your approval."
      />
      {item ? (
        <Detail ref_={item} onBack={() => setParams({})} />
      ) : (
        <>
          <Tabs
            label="Feedback filters"
            tabs={QUEUE_FILTERS.map((f) => ({ id: f.id, label: counts.data ? `${f.label} (${queueFilterCount(f.id, c)})` : f.label }))}
            value={filter}
            onChange={(id) => setParams(id === "attention" ? {} : { filter: id })}
          />
          <div role="tabpanel" id={`panel-${filter}`} aria-labelledby={`tab-${filter}`}>
            <ItemList filter={filter} />
          </div>
          <GoodToKnow>
            The feedback agent runs every ten minutes on the team&apos;s Mac. It builds safe changes as pull requests with tests, asks the sender when
            something is unclear, and holds anything about billing, sign-in and permissions, customer wording, legal text, data deletion, AI prompts or
            costs for your approval. It never merges or deploys.
          </GoodToKnow>
        </>
      )}
    </>
  );
}
