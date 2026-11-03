/**
 * Ask Stackurity: shown under the answers once a conversation is long or
 * has cost a lot (the server's `long_chat` on `done`). A suggestion only:
 * the person can keep asking here.
 */
export function AskLongChat({ onNew }: { onNew: () => void }) {
  return (
    <p className="ask-note small ask-long-chat" role="status">
      This chat is getting long. Start a new chat for better answers.{" "}
      <button type="button" className="btn btn-sm btn-link" onClick={onNew}>
        New chat
      </button>
    </p>
  );
}
