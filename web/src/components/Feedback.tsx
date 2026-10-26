import { useRef, useState, type FormEvent } from "react";
import { Link, useLocation } from "react-router";
import { api, ApiError } from "../api";
import { useAuth } from "../auth";
import { ErrorBox } from "./ui";
import { IconMessage } from "./Icons";

type Kind = "bug" | "idea" | "question";

const KINDS: { id: Kind; label: string }[] = [
  { id: "bug", label: "Report a problem" },
  { id: "idea", label: "Suggest an improvement" },
  { id: "question", label: "Ask a question" },
];

const MAX = 5000;

/**
 * Send feedback: a button in the top bar and the dialog it opens. The server
 * forwards the message to the Stackurity team (POST /feedback); the button is
 * hidden when the operator turned feedback off.
 */
export function FeedbackButton() {
  const { me } = useAuth();
  const { pathname } = useLocation();
  const ref = useRef<HTMLDialogElement>(null);
  const messageRef = useRef<HTMLTextAreaElement>(null);
  const [kind, setKind] = useState<Kind>("bug");
  const [message, setMessage] = useState("");
  const [email, setEmail] = useState("");
  const [page, setPage] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [sent, setSent] = useState(false);

  if (!me?.feedback_enabled || !me.user) return null;

  const open = () => {
    if (sent) {
      setSent(false);
      setMessage("");
      setKind("bug");
    }
    setEmail((e) => e || me.user?.email || "");
    setPage(pathname);
    setError(null);
    ref.current?.showModal();
    messageRef.current?.focus();
  };
  const close = () => ref.current?.close();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post("/feedback", { kind, message, email: email.trim(), page });
      setSent(true);
    } catch (err) {
      setError(err instanceof ApiError ? err : new ApiError(0, "", "The feedback could not be sent."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <button type="button" className="btn btn-sm btn-link topbar-feedback" onClick={open} aria-haspopup="dialog">
        <IconMessage size={16} />
        <span className="topbar-feedback-label">Feedback</span>
      </button>
      <dialog ref={ref} className="dialog feedback-dialog" aria-labelledby="feedback-title" onClose={() => setError(null)}>
        <header className="dialog-head">
          <h2 id="feedback-title">Send feedback</h2>
          <button type="button" className="btn btn-sm btn-link" onClick={close}>
            Close
          </button>
        </header>
        {sent ? (
          <div className="dialog-body">
            <div className="alert alert-success" role="status">
              Thanks, it went to the Stackurity team.
              {email.trim() ? " If a reply is needed, it will go to " + email.trim() + "." : ""}
            </div>
            <div className="form-actions">
              <button type="button" className="btn btn-primary" onClick={close}>
                Done
              </button>
            </div>
          </div>
        ) : (
          <form className="dialog-body form" onSubmit={submit}>
            <div className="field" role="group" aria-labelledby="feedback-kind">
              <span className="label" id="feedback-kind">
                What is it about?
              </span>
              <div className="feedback-kinds">
                {KINDS.map((k) => (
                  <button key={k.id} type="button" className="kind-choice" aria-pressed={kind === k.id} onClick={() => setKind(k.id)}>
                    {k.label}
                  </button>
                ))}
              </div>
            </div>
            <div className="field">
              <label htmlFor="feedback-message">Message</label>
              <textarea
                id="feedback-message"
                ref={messageRef}
                rows={6}
                required
                maxLength={MAX}
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder={
                  kind === "bug" ? "What happened, and what did you expect?" : kind === "idea" ? "What would make Stackurity better for you?" : "What would you like to know?"
                }
              />
              {message.length > MAX - 500 && <p className="hint">{(MAX - message.length).toLocaleString()} characters left</p>}
            </div>
            <div className="field">
              <label htmlFor="feedback-email">Email for a reply (optional)</label>
              <input id="feedback-email" type="email" autoComplete="email" maxLength={200} value={email} onChange={(e) => setEmail(e.target.value)} />
              <p className="hint">Clear it to send without an email address.</p>
            </div>
            <p className="hint feedback-sent-what">
              What will be sent: your message, email if given, this page&apos;s path{page ? <> (<code>{page}</code>)</> : null} and the Stackurity version;
              no findings or asset names. <Link to="/help/feedback" onClick={close}>More</Link>
            </p>
            <ErrorBox error={error} title="Not sent" />
            <div className="form-actions">
              <button type="submit" className="btn btn-primary" disabled={busy || !message.trim()}>
                {busy ? "Sending…" : "Send feedback"}
              </button>
              <button type="button" className="btn" onClick={close}>
                Cancel
              </button>
            </div>
          </form>
        )}
      </dialog>
    </>
  );
}
