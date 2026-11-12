import { useEffect, useState } from "react";
import { NUDGE, readNudge, shouldNudge, updateNudge } from "../feedbackNudge";
import { IconMessage } from "./Icons";

/**
 * Now and then, a small card in the corner asks whether there is anything to
 * tell the team. It never blocks the page: it waits a few minutes into a visit,
 * skips someone's first day, comes back at most once a week (two weeks after
 * they sent feedback) and stops for good on "Don't ask again". Rules in
 * feedbackNudge.ts.
 */
export function FeedbackNudge({ userId, onOpen, hold }: { userId: number; onOpen: () => void; hold: boolean }) {
  const [show, setShow] = useState(false);

  useEffect(() => {
    const s = readNudge(userId, Date.now());
    if (!s || s.never) return;
    const t = window.setTimeout(() => {
      const now = Date.now();
      const cur = readNudge(userId, now);
      if (!cur || !shouldNudge(cur, now)) return;
      // Not over a dialog that is open (Send feedback itself, a confirmation).
      if (document.querySelector("dialog[open]")) return;
      updateNudge(userId, { lastAsked: now }, now);
      setShow(true);
    }, NUDGE.minVisitMs);
    return () => window.clearTimeout(t);
  }, [userId]);

  if (!show || hold) return null;
  const close = () => setShow(false);
  return (
    <aside className="feedback-nudge" aria-label="Feedback">
      <p className="feedback-nudge-title">
        <IconMessage size={16} /> How is Stackurity working for you?
      </p>
      <p className="feedback-nudge-text">Anything confusing, broken or missing? Tell us in a line or two. It goes straight to the team, and you can add a screenshot.</p>
      <div className="feedback-nudge-actions">
        <button
          type="button"
          className="btn btn-primary btn-sm"
          aria-haspopup="dialog"
          onClick={() => {
            close();
            onOpen();
          }}
        >
          Send feedback
        </button>
        <button type="button" className="btn btn-sm" onClick={close}>
          Not now
        </button>
        <button
          type="button"
          className="btn btn-link btn-sm"
          onClick={() => {
            updateNudge(userId, { never: true }, Date.now());
            close();
          }}
        >
          Don't ask again
        </button>
      </div>
    </aside>
  );
}
