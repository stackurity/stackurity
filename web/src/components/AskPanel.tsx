import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link, useLocation } from "react-router";
import { api, ApiError, getActiveProject } from "../api";
import {
  AskHTTPError,
  noticeText,
  PAGE_LABEL,
  pageOf,
  parseBlocks,
  parseInline,
  streamQuestion,
  type AskConversation,
  type AskMessage,
  type AskPage,
  type AskSettings,
  type AskStatus,
  type Inline,
} from "../ask";
import { Card, ErrorBox, RelativeTime } from "./ui";
import { IconMessage } from "./Icons";

/** Renders an answer: text, bold, code, lists, and links to Stackurity pages only (ask.ts). */
export function AskAnswer({ text, onNavigate }: { text: string; onNavigate?: () => void }) {
  const inline = (parts: Inline[]): ReactNode[] =>
    parts.map((p, i) => {
      switch (p.kind) {
        case "bold":
          return <strong key={i}>{inline(p.parts)}</strong>;
        case "code":
          return (
            <code key={i} className="code">
              {p.text}
            </code>
          );
        case "link":
          return (
            <Link key={i} to={p.to} onClick={onNavigate}>
              {p.text}
            </Link>
          );
        default:
          return <span key={i}>{p.text}</span>;
      }
    });
  return (
    <div className="ask-answer">
      {parseBlocks(text).map((b, i) => {
        if (b.kind === "code") return <pre key={i} className="ask-code">{b.text}</pre>;
        if (b.kind === "list") {
          const items = b.items.map((it, j) => <li key={j}>{inline(parseInline(it))}</li>);
          return b.ordered ? <ol key={i}>{items}</ol> : <ul key={i}>{items}</ul>;
        }
        return (
          <p key={i}>
            {b.lines.map((l, j) => (
              <span key={j}>
                {j > 0 && <br />}
                {inline(parseInline(l))}
              </span>
            ))}
          </p>
        );
      })}
    </div>
  );
}

/** The top bar's button; hidden when the server has no model provider. */
export function AskButton({ status, onOpen }: { status: AskStatus | undefined; onOpen: () => void }) {
  if (!status || status.reason === "not_configured") return null;
  return (
    <button type="button" className="btn btn-sm topbar-ask" onClick={onOpen} aria-haspopup="dialog" title="Ask Stackurity (Alt+K)">
      <IconMessage size={16} />
      <span className="topbar-ask-label">Ask</span>
    </button>
  );
}

interface Turn {
  role: "user" | "assistant" | "notice";
  text: string;
}

const REASONS: Record<string, string> = {
  ask_disabled: "An administrator of this organisation has turned Ask Stackurity off. Admins can turn it on under Settings → AI assistants.",
  plan_required: "Ask Stackurity is not included in this organisation's plan.",
  read_only: "Ask Stackurity is off while the organisation is read-only.",
  spend_cap: "This organisation's Ask Stackurity budget for the month is used up. It is back on the 1st.",
};

/** The panel: on every page, opened from the top bar. */
export function AskPanel({ open, onClose, status, reload }: { open: boolean; onClose: () => void; status: AskStatus | undefined; reload: () => void }) {
  const { pathname } = useLocation();
  const [convs, setConvs] = useState<AskConversation[]>([]);
  const [conv, setConv] = useState<number | null>(null);
  const [turns, setTurns] = useState<Turn[]>([]);
  const [draft, setDraft] = useState("");
  const [tool, setTool] = useState("");
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [usePage, setUsePage] = useState(true);
  const abort = useRef<AbortController | null>(null);
  const input = useRef<HTMLTextAreaElement>(null);
  const end = useRef<HTMLDivElement>(null);
  const page: AskPage | null = pageOf(pathname);

  useEffect(() => setUsePage(true), [pathname]);
  useEffect(() => end.current?.scrollIntoView({ block: "end" }), [turns, draft, tool]);
  useEffect(() => {
    if (!open) return;
    input.current?.focus();
    api.get<{ items: AskConversation[] }>("/ask/conversations").then((r) => setConvs(r.items), () => undefined);
  }, [open]);
  useEffect(() => () => abort.current?.abort(), []);

  if (!open) return null;

  const fail = (e: unknown) => setError(e instanceof ApiError ? e : new ApiError(0, "error", e instanceof Error ? e.message : String(e)));

  const accept = async () => {
    try {
      await api.post("/ask/notice", { version: status?.notice_version });
      reload();
    } catch (e) {
      fail(e);
    }
  };

  const openConv = async (id: number) => {
    setHistory(false);
    setError(null);
    try {
      const r = await api.get<{ messages: AskMessage[] }>(`/ask/conversations/${id}`);
      setConv(id);
      setTurns(
        r.messages.map((m) =>
          m.stop_reason === "refusal" && !m.text
            ? { role: "notice", text: "Claude declined to answer this question." }
            : { role: m.role, text: m.text },
        ),
      );
    } catch (e) {
      fail(e);
    }
  };

  const fresh = () => {
    setConv(null);
    setTurns([]);
    setHistory(false);
    setError(null);
    input.current?.focus();
  };

  const remove = async (id: number) => {
    if (!window.confirm("Delete this conversation? It cannot be brought back.")) return;
    try {
      await api.del(`/ask/conversations/${id}`);
      setConvs((cs) => cs.filter((c) => c.id !== id));
      if (conv === id) fresh();
    } catch (e) {
      fail(e);
    }
  };

  const removeAll = async () => {
    if (!window.confirm("Delete all your conversations in this organisation? They cannot be brought back.")) return;
    try {
      await api.del("/ask/conversations");
      setConvs([]);
      fresh();
    } catch (e) {
      fail(e);
    }
  };

  const send = async (ev?: FormEvent) => {
    ev?.preventDefault();
    const q = text.trim();
    if (!q || busy) return;
    setError(null);
    setBusy(true);
    let id = conv;
    try {
      if (id === null) {
        const c = await api.post<AskConversation>("/ask/conversations", {});
        id = c.id;
        setConv(c.id);
        setConvs((cs) => [{ ...c, title: q }, ...cs]);
      }
    } catch (e) {
      fail(e);
      setBusy(false);
      return;
    }
    setText("");
    setTurns((t) => [...t, { role: "user", text: q }]);
    setDraft("");
    setTool("");
    const ctl = new AbortController();
    abort.current = ctl;
    let answer = "";
    let closing: Turn | null = null;
    try {
      await streamQuestion(id, q, usePage ? page : null, getActiveProject(), (e) => {
        switch (e.event) {
          case "text":
            answer += String(e.data.text ?? "");
            setDraft(answer);
            setTool("");
            break;
          case "reset":
            answer = "";
            setDraft("");
            break;
          case "tool":
            setTool(String(e.data.tool ?? "Reading"));
            break;
          case "done":
            if (e.data.message) closing = { role: "notice", text: String(e.data.message) };
            break;
          case "error":
            closing = { role: "notice", text: String(e.data.message ?? "Something went wrong.") };
            break;
        }
      }, ctl.signal);
    } catch (e) {
      if (e instanceof AskHTTPError) closing = { role: "notice", text: e.message };
      else if (!(e instanceof DOMException && e.name === "AbortError")) closing = { role: "notice", text: "The connection to Stackurity was lost." };
    } finally {
      abort.current = null;
      setBusy(false);
      setDraft("");
      setTool("");
      setTurns((t) => [...t, ...(answer ? [{ role: "assistant" as const, text: answer }] : []), ...(closing ? [closing] : [])]);
      reload();
    }
  };

  const stop = () => abort.current?.abort();
  const s = status;
  const blocked = s && !s.available ? REASONS[s.reason] ?? s.message : "";
  const left =
    s && s.questions_limit !== null && s.questions_limit !== undefined
      ? `${Math.max(0, s.questions_limit - s.questions_used)} of ${s.questions_limit} questions left${s.question_period === "total" ? "" : " this month"}`
      : "";

  return (
    <aside className="ask-panel" role="dialog" aria-modal="false" aria-label="Ask Stackurity" onKeyDown={(e) => e.key === "Escape" && onClose()}>
      <header className="ask-head">
        <strong>Ask Stackurity</strong>
        <span className="ask-head-actions">
          {s?.notice_accepted && (
            <>
              <button type="button" className="btn btn-sm btn-link" onClick={() => setHistory((h) => !h)} aria-expanded={history}>
                History
              </button>
              <button type="button" className="btn btn-sm btn-link" onClick={fresh}>
                New
              </button>
            </>
          )}
          <button type="button" className="btn btn-sm btn-link" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </span>
      </header>
      <ErrorBox error={error} title="Ask Stackurity" />
      {!s ? (
        <p className="muted ask-body">Loading…</p>
      ) : !s.notice_accepted ? (
        <div className="ask-body ask-notice">
          <h3>Before your first question</h3>
          {noticeText(s.provider).map((p, i) => (
            <p key={i}>{p}</p>
          ))}
          <p className="small muted">
            More in <Link to="/help/ai-assistants">Help</Link>.
          </p>
          <button type="button" className="btn btn-primary" onClick={() => void accept()}>
            I understand
          </button>
        </div>
      ) : history ? (
        <div className="ask-body">
          {convs.length === 0 ? (
            <p className="muted">No conversations yet. They are deleted 30 days after you start them.</p>
          ) : (
            <ul className="ask-history">
              {convs.map((c) => (
                <li key={c.id}>
                  <button type="button" className="btn-link ask-history-open" onClick={() => void openConv(c.id)}>
                    {c.title || "Untitled"}
                  </button>
                  <span className="small muted">
                    <RelativeTime iso={c.updated_at} />
                  </span>
                  <button type="button" className="btn btn-sm btn-link-danger" onClick={() => void remove(c.id)} aria-label={`Delete ${c.title || "conversation"}`}>
                    Delete
                  </button>
                </li>
              ))}
            </ul>
          )}
          {convs.length > 0 && (
            <button type="button" className="btn btn-sm btn-link-danger" onClick={() => void removeAll()}>
              Delete all my conversations
            </button>
          )}
        </div>
      ) : (
        <>
          <div className="ask-body ask-log" aria-live="polite">
            {turns.length === 0 && !busy && (
              <div className="muted">
                <p>Ask about your inventory, issues and fixes. For example:</p>
                <ul>
                  <li>What should we fix first this week?</li>
                  <li>Which servers run an end-of-life version of PHP?</li>
                  <li>Was CVE-2024-3094 fixed everywhere?</li>
                </ul>
                <p className="small">Answers can be wrong: check the linked pages.</p>
              </div>
            )}
            {turns.map((t, i) =>
              t.role === "user" ? (
                <div key={i} className="ask-q">
                  {t.text}
                </div>
              ) : t.role === "assistant" ? (
                <AskAnswer key={i} text={t.text} />
              ) : (
                <p key={i} className="ask-note small">
                  {t.text}
                </p>
              ),
            )}
            {draft && <AskAnswer text={draft} />}
            {busy && <p className="small muted ask-tool">{tool ? `${tool}…` : "Thinking…"}</p>}
            <div ref={end} />
          </div>
          <form className="ask-form" onSubmit={(e) => void send(e)}>
            {blocked && <p className="ask-note small">{blocked}</p>}
            {page && usePage && (
              <p className="ask-page small">
                About {PAGE_LABEL[page.kind]}{" "}
                <button type="button" className="btn-link small" onClick={() => setUsePage(false)} aria-label="Do not use the page open">
                  (remove)
                </button>
              </p>
            )}
            <textarea
              ref={input}
              value={text}
              rows={3}
              maxLength={4000}
              placeholder="Ask a question"
              aria-label="Your question"
              disabled={Boolean(blocked)}
              onChange={(e) => setText(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  void send();
                }
              }}
            />
            <div className="ask-form-row">
              <span className="small muted">{left}</span>
              {busy ? (
                <button type="button" className="btn btn-sm" onClick={stop}>
                  Stop
                </button>
              ) : (
                <button type="submit" className="btn btn-sm btn-primary" disabled={!text.trim() || Boolean(blocked)}>
                  Ask
                </button>
              )}
            </div>
          </form>
        </>
      )}
    </aside>
  );
}

/**
 * Settings → AI assistants: the organisation admin's switch for Ask
 * Stackurity, this month's use, and deleting every conversation (which
 * admins can do but never read).
 */
export function AskSettingsCard() {
  const [s, setS] = useState<AskSettings | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const [deleted, setDeleted] = useState<number | null>(null);
  useEffect(() => {
    api.get<AskSettings>("/ask/settings").then(setS, (e: ApiError) => setError(e));
  }, []);
  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, "error", String(e)));
    } finally {
      setBusy(false);
    }
  };
  const toggle = (enabled: boolean) => {
    if (enabled && !window.confirm(noticeText(s?.provider ?? "anthropic")[0] + "\n\nTurn Ask Stackurity on for everyone in this organisation?")) return;
    void run(async () => setS(await api.put<AskSettings>("/ask/settings", { enabled })));
  };
  const deleteAll = () => {
    if (!window.confirm("Delete every Ask Stackurity conversation in this organisation, whoever had it? They cannot be brought back.")) return;
    void run(async () => setDeleted((await api.del<{ deleted: number }>("/ask/settings/conversations")).deleted));
  };
  if (error?.status === 403) return null; // not an organisation admin
  return (
    <Card title="Ask Stackurity">
      <ErrorBox error={error} title="Ask Stackurity settings" />
      {!s ? (
        !error && <p className="muted">Loading…</p>
      ) : !s.configured ? (
        <p className="muted">
          Not set up on this server. Whoever runs it can turn it on with a model provider (<code>STACKURITY_ANTHROPIC_API_KEY</code>, Amazon Bedrock
          or Vertex AI); see <Link to="/help/ai-assistants">Help</Link>.
        </p>
      ) : (
        <>
          <p>
            An assistant in a panel on every page: people ask about your inventory, issues and fixes, and Claude answers from what each of them may
            see, with links to the pages it used. Questions and the data read to answer them go to {providerWordsShort(s.provider)}.
          </p>
          <label>
            <input type="checkbox" checked={s.enabled} disabled={busy} onChange={(e) => toggle(e.target.checked)} /> Turn on Ask Stackurity for this
            organisation
          </label>
          <p className="small muted">
            {s.questions_this_month} questions this month
            {s.question_limit !== null ? ` of ${s.question_limit}${s.question_period === "total" ? " in total" : ""}` : ""}
            {s.spend_cap_micros !== null ? `, $${(s.spend_this_month_micros / 1e6).toFixed(2)} of a $${(s.spend_cap_micros / 1e6).toFixed(2)} monthly budget` : ""}.
            Model: {s.model}.
          </p>
          <p className="small muted">
            Conversations are kept 30 days. You can delete everyone&apos;s, but not read them.{" "}
            <button type="button" className="btn btn-sm btn-link-danger" disabled={busy} onClick={deleteAll}>
              Delete all conversations
            </button>
            {deleted !== null && <> Deleted {deleted}.</>}
          </p>
        </>
      )}
    </Card>
  );
}

function providerWordsShort(provider: string): string {
  return provider === "bedrock" ? "Amazon Bedrock" : provider === "vertex" ? "Google Vertex AI" : "Anthropic in the United States";
}
