import { useRef, useState } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { useAction, useLoad } from "../hooks";
import { absTime } from "../format";
import {
  canReply,
  commentAuthor,
  FEEDBACK_REPLY_MAX,
  feedbackKindLabel,
  feedbackStatusLabel,
  feedbackStatusTone,
  type FeedbackItem,
  type MyFeedback,
} from "../feedback";
import { Badge } from "../components/Badge";
import { FeedbackDialog, feedbackAvailable, type FeedbackHandle } from "../components/Feedback";
import { EmptyState, ErrorBox, Loading, Notice, PageHeader, RelativeTime } from "../components/ui";

function sentDate(iso: string): string {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function Status({ it }: { it: FeedbackItem }) {
  return <Badge status={it.status} tone={feedbackStatusTone(it.status)} label={feedbackStatusLabel(it.status, it.fixed_in)} />;
}

/** The team's note: plain text, line breaks kept. */
function Note({ text }: { text: string }) {
  if (!text.trim()) return null;
  return <p className="feedback-note">{text}</p>;
}

function Sent({ iso }: { iso: string }) {
  return (
    <time dateTime={iso} title={absTime(iso)}>
      {sentDate(iso)}
    </time>
  );
}

/**
 * The conversation on one item: the team's questions and updates (some
 * written by the automated feedback agent, and labelled so) and the
 * person's replies, with a reply box while the item is open. Open by
 * default when the team is waiting for an answer.
 */
function Thread({ it, onReplied }: { it: FeedbackItem; onReplied: () => void }) {
  const thread = it.thread ?? [];
  const open = canReply(it.status);
  const act = useAction();
  const [text, setText] = useState("");
  const [sent, setSent] = useState(false);
  if (thread.length === 0 && !open) return null;
  const id = `reply-${it.ref}`;
  const waiting = it.status === "needs_info";
  const send = async () => {
    const message = text.trim();
    if (!message) return;
    if (await act.run(() => api.post(`/feedback/mine/${encodeURIComponent(it.ref)}/reply`, { message }))) {
      setText("");
      setSent(true);
      onReplied();
    }
  };
  return (
    <details className="feedback-thread" open={waiting || undefined}>
      <summary>
        {waiting ? "The team asked you something: answer here" : thread.length > 0 ? `Conversation (${thread.length})` : "Add a detail"}
      </summary>
      {thread.length > 0 && (
        <ol className="feedback-comments">
          {thread.map((c, i) => (
            <li key={i} className={`feedback-comment feedback-comment-${c.from === "sender" ? "mine" : "team"}`}>
              <span className="small muted">
                {commentAuthor(c.from)}
                {c.kind === "question" ? " asked" : ""} · <RelativeTime iso={c.at} />
              </span>
              <p className="feedback-comment-body">{c.body}</p>
            </li>
          ))}
        </ol>
      )}
      {sent && <Notice kind="success">Reply sent to the Stackurity team.</Notice>}
      {open && (
        <form
          className="form feedback-reply"
          onSubmit={(e) => {
            e.preventDefault();
            void send();
          }}
        >
          <div className="field">
            <label htmlFor={id}>{waiting ? "Your answer" : "Add a detail"}</label>
            <textarea id={id} rows={3} maxLength={FEEDBACK_REPLY_MAX} value={text} onChange={(e) => setText(e.target.value)} />
            <span className="hint">The Stackurity team and its feedback agent read it. Don&apos;t include passwords or keys.</span>
          </div>
          <button type="submit" className="btn btn-primary btn-sm" disabled={act.pending || !text.trim()}>
            {act.pending ? "Sending…" : "Send reply"}
          </button>
          <ErrorBox error={act.error} title="Could not send the reply" />
        </form>
      )}
    </details>
  );
}

/** My feedback: what the signed-in person sent with Send feedback, and where each item is. */
export function MyFeedbackPage() {
  const { me } = useAuth();
  const dialog = useRef<FeedbackHandle>(null);
  const r = useLoad(() => api.get<MyFeedback>("/feedback/mine"), []);
  const canSend = feedbackAvailable(me);
  const items = r.data?.items ?? [];

  return (
    <>
      <PageHeader
        title="My feedback"
        sub="What you sent to the Stackurity team, and where each item is."
        help="feedback"
        actions={
          canSend && items.length > 0 ? (
            <button type="button" className="btn btn-primary" aria-haspopup="dialog" onClick={() => dialog.current?.open()}>
              Send feedback
            </button>
          ) : undefined
        }
      />
      <ErrorBox error={r.error} title="Could not load your feedback" />
      {r.data?.check_failed && (
        <p className="feedback-check-failed muted" role="status">
          Couldn&apos;t reach the Stackurity team&apos;s server just now; statuses may be out of date.
        </p>
      )}
      {r.loading && !r.data ? (
        <Loading />
      ) : r.data && items.length === 0 ? (
        <EmptyState title="Nothing sent yet." help="feedback">
          {canSend && (
            <button type="button" className="btn btn-primary" aria-haspopup="dialog" onClick={() => dialog.current?.open()}>
              Send feedback
            </button>
          )}
        </EmptyState>
      ) : items.length > 0 ? (
        <>
          <div className="table-wrap only-wide">
            <table className="table feedback-table">
              <thead>
                <tr>
                  <th scope="col">Ref</th>
                  <th scope="col">Type</th>
                  <th scope="col">Summary</th>
                  <th scope="col">Sent</th>
                  <th scope="col">Status</th>
                </tr>
              </thead>
              <tbody>
                {items.map((it) => (
                  <tr key={it.ref}>
                    <td className="mono">{it.ref}</td>
                    <td>{feedbackKindLabel(it.kind)}</td>
                    <td className="feedback-summary">
                      {it.summary}
                      {it.attachments > 0 && <span className="muted small"> · {it.attachments === 1 ? "1 attachment" : `${it.attachments} attachments`}</span>}
                      <Note text={it.status_note} />
                      <Thread it={it} onReplied={r.reload} />
                    </td>
                    <td>
                      <Sent iso={it.created_at} />
                    </td>
                    <td>
                      <Status it={it} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <ul className="finding-cards feedback-cards only-narrow" aria-label="My feedback">
            {items.map((it) => (
              <li key={it.ref} className="finding-card">
                <div className="finding-card-top">
                  <span className="mono">{it.ref}</span>
                  <Status it={it} />
                </div>
                <span className="finding-card-title feedback-summary">{it.summary}</span>
                <span className="muted small">
                  {feedbackKindLabel(it.kind)} · sent <Sent iso={it.created_at} />
                  {it.attachments > 0 && ` · ${it.attachments === 1 ? "1 attachment" : `${it.attachments} attachments`}`}
                </span>
                <Note text={it.status_note} />
                <Thread it={it} onReplied={r.reload} />
              </li>
            ))}
          </ul>
        </>
      ) : null}
      <FeedbackDialog ref={dialog} onSent={r.reload} />
    </>
  );
}
