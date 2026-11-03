import { forwardRef, useImperativeHandle, useRef, useState, type FormEvent } from "react";
import { Link, useLocation } from "react-router";
import { api, ApiError, type Me } from "../api";
import { useAuth } from "../auth";
import {
  ATTACH_ACCEPT,
  checkAttachments,
  FEEDBACK_KINDS,
  FEEDBACK_MAX_CHARS as MAX,
  feedbackForm,
  formatBytes,
  MAX_FILES,
  type FeedbackKind,
} from "../feedback";
import { ErrorBox } from "./ui";
import { IconMessage } from "./Icons";

/** Whether Send feedback is offered to this session (the operator can turn it off). */
export function feedbackAvailable(me: Me | null | undefined): boolean {
  return Boolean(me?.feedback_enabled && me.user);
}

/** Opens the Send feedback dialog; see FeedbackDialog. */
export interface FeedbackHandle {
  open: () => void;
}

/**
 * Send feedback: a button in the top bar and the dialog it opens. The server
 * forwards the message to the Stackurity team (POST /feedback); the button is
 * hidden when the operator turned feedback off.
 */
export function FeedbackButton() {
  const ref = useRef<FeedbackHandle>(null);
  const { me } = useAuth();
  if (!feedbackAvailable(me)) return null;
  return (
    <>
      <button type="button" className="btn btn-sm btn-link topbar-feedback" onClick={() => ref.current?.open()} aria-haspopup="dialog">
        <IconMessage size={16} />
        <span className="topbar-feedback-label">Feedback</span>
      </button>
      <FeedbackDialog ref={ref} />
    </>
  );
}

function sameFile(a: File, b: File): boolean {
  return a.name === b.name && a.size === b.size && a.lastModified === b.lastModified;
}

/**
 * The Send feedback dialog on its own, for menus: mount it once outside the
 * menu (so closing the menu does not unmount it) and call open() on its ref.
 * It renders nothing when feedback is off. onSent runs after a send succeeds.
 */
export const FeedbackDialog = forwardRef<FeedbackHandle, { onSent?: () => void }>(function FeedbackDialog({ onSent }, handle) {
  const { me } = useAuth();
  const { pathname } = useLocation();
  const ref = useRef<HTMLDialogElement>(null);
  const messageRef = useRef<HTMLTextAreaElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const [kind, setKind] = useState<FeedbackKind>("issue");
  const [message, setMessage] = useState("");
  const [email, setEmail] = useState("");
  const [page, setPage] = useState("");
  const [files, setFiles] = useState<File[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [sent, setSent] = useState<{ ref?: string } | null>(null);

  const check = checkAttachments(files);

  const open = () => {
    if (sent) {
      setSent(null);
      setMessage("");
      setKind("issue");
      setFiles([]);
    }
    setEmail((e) => e || me?.user?.email || "");
    setPage(pathname);
    setError(null);
    ref.current?.showModal();
    messageRef.current?.focus();
  };
  const close = () => ref.current?.close();
  useImperativeHandle(handle, () => ({ open }));

  const addFiles = (list: FileList | null) => {
    if (!list || list.length === 0) return;
    const picked = Array.from(list);
    setFiles((cur) => [...cur, ...picked.filter((f) => !cur.some((c) => sameFile(c, f)))]);
    // Let the same file be chosen again after it is removed.
    if (fileRef.current) fileRef.current.value = "";
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!check.ok) return;
    setBusy(true);
    setError(null);
    const fields = {
      kind,
      message,
      email: email.trim(),
      page,
      viewport: `${window.innerWidth}x${window.innerHeight}`,
    };
    try {
      const r =
        files.length > 0
          ? await api.postForm<{ status: string; ref?: string }>("/feedback", feedbackForm(fields, files))
          : await api.post<{ status: string; ref?: string }>("/feedback", fields);
      setSent({ ref: r?.ref || undefined });
      onSent?.();
    } catch (err) {
      setError(err instanceof ApiError ? err : new ApiError(0, "", "The feedback could not be sent."));
    } finally {
      setBusy(false);
    }
  };

  if (!feedbackAvailable(me) || !me?.user) return null;

  const placeholder = FEEDBACK_KINDS.find((k) => k.id === kind)?.placeholder;

  return (
    <>
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
              {sent.ref ? (
                <>
                  Thanks — your reference is <strong className="mono">{sent.ref}</strong>.
                </>
              ) : (
                "Thanks — it went to the Stackurity team."
              )}
              {email.trim() ? " If a reply is needed, it will go to " + email.trim() + "." : ""}
            </div>
            <div className="form-actions">
              <button type="button" className="btn btn-primary" onClick={close}>
                Done
              </button>
              <Link to="/feedback" className="btn" onClick={close}>
                See My feedback
              </Link>
            </div>
          </div>
        ) : (
          <form className="dialog-body form" onSubmit={submit} aria-busy={busy}>
            <fieldset className="feedback-fieldset" disabled={busy}>
              <div className="field" role="group" aria-labelledby="feedback-kind">
                <span className="label" id="feedback-kind">
                  Type
                </span>
                <div className="feedback-kinds">
                  {FEEDBACK_KINDS.map((k) => (
                    <button key={k.id} type="button" className="kind-choice" aria-pressed={kind === k.id} onClick={() => setKind(k.id)}>
                      {k.label}
                    </button>
                  ))}
                </div>
              </div>
              <div className="field">
                <label htmlFor="feedback-message">Description</label>
                <textarea
                  id="feedback-message"
                  ref={messageRef}
                  rows={6}
                  required
                  maxLength={MAX}
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  placeholder={placeholder}
                />
                {message.length > MAX - 500 && <p className="hint">{(MAX - message.length).toLocaleString()} characters left</p>}
              </div>
              <div className="field">
                <span className="label" id="feedback-files-label">
                  Attachments (optional)
                </span>
                <p className="feedback-warning" role="note">
                  Screenshots may contain your data and will be sent to the Stackurity team.
                </p>
                <input
                  ref={fileRef}
                  id="feedback-files"
                  className="sr-only"
                  type="file"
                  multiple
                  accept={ATTACH_ACCEPT}
                  tabIndex={-1}
                  aria-labelledby="feedback-files-label"
                  onChange={(e) => addFiles(e.target.files)}
                />
                <div className="feedback-attach-row">
                  <button type="button" className="btn btn-sm" onClick={() => fileRef.current?.click()} disabled={files.length >= MAX_FILES}>
                    Add files
                  </button>
                  <span className="hint">Up to {MAX_FILES} images, videos or PDFs: 10 MB each (videos 50 MB), 90 MB together.</span>
                </div>
                {files.length > 0 && (
                  <ul className="feedback-files" aria-label="Attached files">
                    {files.map((f, i) => (
                      <li key={`${f.name}-${f.size}-${f.lastModified}`} className={check.fileErrors[i] ? "has-error" : undefined}>
                        <span className="feedback-file-name">{f.name}</span>
                        <span className="feedback-file-size muted small">{formatBytes(f.size)}</span>
                        <button
                          type="button"
                          className="btn btn-sm btn-link"
                          onClick={() => setFiles((cur) => cur.filter((_, j) => j !== i))}
                          aria-label={`Remove ${f.name}`}
                        >
                          Remove
                        </button>
                        {check.fileErrors[i] && (
                          <span className="hint hint-error feedback-file-error" role="alert">
                            {check.fileErrors[i]}
                          </span>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
                {check.errors.map((m) => (
                  <p key={m} className="hint hint-error" role="alert">
                    {m}
                  </p>
                ))}
              </div>
              <div className="field">
                <label htmlFor="feedback-email">Email for a reply (optional)</label>
                <input id="feedback-email" type="email" autoComplete="email" maxLength={200} value={email} onChange={(e) => setEmail(e.target.value)} />
                <p className="hint">Clear it to send without an email address.</p>
              </div>
            </fieldset>
            <p className="hint feedback-sent-what">
              What will be sent: your description, any attachments, email if given, this page&apos;s path{page ? <> (<code>{page}</code>)</> : null}, your
              browser and window size, and the Stackurity version; no findings or asset names.{" "}
              <Link to="/help/feedback" onClick={close}>
                More
              </Link>
            </p>
            <ErrorBox error={error} title="Not sent" />
            <div className="form-actions">
              <button type="submit" className="btn btn-primary" disabled={busy || !message.trim() || !check.ok}>
                {busy ? "Sending…" : "Send feedback"}
              </button>
              <button type="button" className="btn" onClick={close} disabled={busy}>
                Cancel
              </button>
            </div>
          </form>
        )}
      </dialog>
    </>
  );
});
