import { useRef } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { useLoad } from "../hooks";
import { absTime } from "../format";
import { feedbackKindLabel, feedbackStatusLabel, feedbackStatusTone, type FeedbackItem, type MyFeedback } from "../feedback";
import { Badge } from "../components/Badge";
import { FeedbackDialog, feedbackAvailable, type FeedbackHandle } from "../components/Feedback";
import { EmptyState, ErrorBox, Loading, PageHeader } from "../components/ui";

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
              </li>
            ))}
          </ul>
        </>
      ) : null}
      <FeedbackDialog ref={dialog} onSent={r.reload} />
    </>
  );
}
