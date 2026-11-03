import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import { api, ApiError } from "../api";
import {
  canSend,
  FEEDBACK_CATEGORIES,
  FEEDBACK_CONSENT_LABEL,
  FEEDBACK_SCOPES,
  FEEDBACK_TEXT_MAX,
  feedbackRequest,
  scopesFor,
  type FeedbackForm,
  type FeedbackRating,
  type FeedbackScope,
} from "../askFeedback";

// Feedback on Ask Stackurity: thumbs under each answer, a "Feedback" item
// in the panel's header, and the form both open (askFeedback.ts says what
// is sent).

const Thumb = ({ down }: { down?: boolean }) => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={down ? { transform: "rotate(180deg)" } : undefined}>
    <path d="M7 10v11" />
    <path d="M15 5.9 14 10h5.8a2 2 0 0 1 1.9 2.6l-2.3 7A2 2 0 0 1 17.5 21H7V10l4-8a3.1 3.1 0 0 1 4 3.9Z" />
  </svg>
);

/** Thumbs up / down under an answer (seq). */
export function AskRate({ conv, seq }: { conv: number; seq: number }) {
  const [rated, setRated] = useState<FeedbackRating | null>(null);
  const [form, setForm] = useState(false);
  const [error, setError] = useState("");
  const up = async () => {
    setError("");
    try {
      const r = feedbackRequest(conv, seq, { rating: "up", scope: "answer", category: "", text: "", consent: false }, here());
      await api.post(r.path, r.body);
      setRated("up");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Not sent.");
    }
  };
  if (rated) return <p className="ask-rate small muted">Thanks for the feedback.</p>;
  return (
    <div className="ask-rate">
      <button type="button" className="btn-link ask-rate-btn" onClick={() => void up()} aria-label="Good answer" title="Good answer">
        <Thumb />
      </button>
      <button type="button" className="btn-link ask-rate-btn" onClick={() => setForm(true)} aria-label="Bad answer" title="Bad answer">
        <Thumb down />
      </button>
      {error && <span className="small text-danger">{error}</span>}
      {form && <AskFeedbackForm conv={conv} seq={seq} rating="down" onClose={() => setForm(false)} onSent={() => setRated("down")} />}
    </div>
  );
}

/** "Feedback" in the panel's header: about the whole chat, or the panel itself. */
export function AskFeedbackButton({ conv }: { conv: number | null }) {
  const [open, setOpen] = useState(false);
  const [sent, setSent] = useState(false);
  useEffect(() => {
    if (!sent) return;
    const t = setTimeout(() => setSent(false), 3000);
    return () => clearTimeout(t);
  }, [sent]);
  return (
    <>
      <button type="button" className="btn btn-sm btn-link" onClick={() => setOpen(true)} aria-haspopup="dialog">
        {sent ? "Thanks" : "Feedback"}
      </button>
      {open && <AskFeedbackForm conv={conv} seq={null} onClose={() => setOpen(false)} onSent={() => setSent(true)} />}
    </>
  );
}

function here() {
  return { href: window.location.href, width: window.innerWidth, height: window.innerHeight };
}

/** The form: what was wrong, what it was about, what they expected, and consent to share. */
export function AskFeedbackForm({
  conv,
  seq,
  rating,
  onClose,
  onSent,
}: {
  conv: number | null;
  seq: number | null;
  rating?: FeedbackRating;
  onClose: () => void;
  onSent: () => void;
}) {
  const scopes = scopesFor(conv, seq);
  const [f, setF] = useState<FeedbackForm>({ rating, category: "", scope: scopes[0], text: "", consent: true });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    box.current?.querySelector<HTMLElement>("select, input, textarea")?.focus();
  }, []);
  const set = (p: Partial<FeedbackForm>) => setF((x) => ({ ...x, ...p }));
  const send = async () => {
    if (!canSend(f) || busy) return;
    setBusy(true);
    setError("");
    try {
      const r = feedbackRequest(conv, seq, f, here());
      await api.post(r.path, r.body);
      onSent();
      onClose();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Your feedback was not sent. Try again.");
    } finally {
      setBusy(false);
    }
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Escape") {
      e.stopPropagation();
      onClose();
    }
  };
  const id = (s: string) => `ask-fb-${s}`;
  return (
    <div className="confirm-backdrop ask-fb-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={box} className="confirm-dialog ask-fb" role="dialog" aria-modal="true" aria-labelledby={id("title")} onKeyDown={onKey}>
        <h2 id={id("title")} className="confirm-title">
          {rating === "down" ? "What went wrong?" : "Send feedback"}
        </h2>
        <div className="confirm-body">
          <div className="field">
            <label htmlFor={id("category")}>What was wrong</label>
            <select id={id("category")} value={f.category} onChange={(e) => set({ category: e.target.value })}>
              <option value="">Choose one</option>
              {FEEDBACK_CATEGORIES.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
            </select>
          </div>
          {scopes.length > 1 && (
            <fieldset className="field ask-fb-scope">
              <legend>What was it about</legend>
              {FEEDBACK_SCOPES.filter((s) => scopes.includes(s.value)).map((s) => (
                <label key={s.value} className="ask-fb-radio">
                  <input type="radio" name={id("scope")} value={s.value} checked={f.scope === s.value} onChange={() => set({ scope: s.value as FeedbackScope })} />{" "}
                  {s.label}
                </label>
              ))}
            </fieldset>
          )}
          <div className="field">
            <label htmlFor={id("text")}>What did you expect? (optional)</label>
            <textarea id={id("text")} rows={3} maxLength={FEEDBACK_TEXT_MAX} value={f.text} onChange={(e) => set({ text: e.target.value })} />
          </div>
          {conv !== null && (
            <label className="ask-fb-consent">
              <input type="checkbox" checked={f.consent} onChange={(e) => set({ consent: e.target.checked })} /> {FEEDBACK_CONSENT_LABEL}
            </label>
          )}
          <p className="small muted ask-fb-note">
            {conv === null
              ? "We keep what you write here, with the page and window size."
              : f.consent
                ? "The Stackurity team will see the messages this is about, with passwords, keys and email addresses removed, for up to 90 days."
                : "We keep only what you choose and write here, not the conversation."}
          </p>
          {error && <p className="text-danger small">{error}</p>}
        </div>
        <div className="confirm-actions">
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button type="button" className="btn btn-primary" disabled={!canSend(f) || busy} onClick={() => void send()}>
            Send feedback
          </button>
        </div>
      </div>
    </div>
  );
}
