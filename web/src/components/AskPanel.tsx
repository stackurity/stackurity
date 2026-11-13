import { useEffect, useLayoutEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link, useLocation } from "react-router";
import { api, ApiError, getActiveProject } from "../api";
import {
  historyGroups,
  ASK_CONSENT_VERSION,
  ASK_NOTICE_VERSION,
  AskHTTPError,
  consentCheckbox,
  consentText,
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
import { Card, CheckCard, ErrorBox, RelativeTime } from "./ui";
import { IconMessage } from "./Icons";
import { confirmAction } from "./ConfirmDialog";
import { AskFeedbackForm, AskRate } from "./AskFeedback";
import { AskLongChat } from "./AskLongChat";
import type { AskPanelState } from "../askState";
import { useProject } from "../project";
import { lookedAt, SECTION_TITLE, structureAnswer } from "../askAnswer";
import { PlaceText } from "./PlaceText";
import { AskProposalCard } from "./AskProposalCard";
import { looksLikeSecret, SECRET_REMOVED_NOTICE, SECRET_TYPING_WARNING } from "../askSecrets";
import { changedLine, proposalsByAnswer, type AskProposal } from "../askProposal";
import { AskAnswerExtras } from "./AskAnswerExtras";

/**
 * Renders an answer. One the model wrote with the known headings
 * (askAnswer.ts) leads with its recommendation, with the reasoning,
 * evidence, alternatives and data gaps in sections that open on a click;
 * data gaps start open, so what Ask could not check is never hidden. Any
 * other answer renders as plain text, lists and links, as it always has.
 */
export function AskAnswer({ text, onNavigate }: { text: string; onNavigate?: () => void }) {
  const s = structureAnswer(text);
  if (!s) return <AnswerText text={text} onNavigate={onNavigate} />;
  return (
    <div className="ask-answer ask-structured">
      {s.lead && (
        <div className="ask-lead">
          <span className="ask-lead-label">Recommendation</span>
          <AnswerText text={s.lead} onNavigate={onNavigate} />
        </div>
      )}
      {s.sections.map((sec, i) => (
        <details key={sec.kind} className={`ask-sec ask-sec-${sec.kind}`} open={sec.kind === "gaps" || (!s.lead && i === 0)}>
          <summary>{SECTION_TITLE[sec.kind]}</summary>
          <AnswerText text={sec.body} onNavigate={onNavigate} />
        </details>
      ))}
    </div>
  );
}

/** Text, bold, code, lists, and links to Stackurity pages only (ask.ts). */
function AnswerText({ text, onNavigate }: { text: string; onNavigate?: () => void }) {
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

/**
 * Under each answer: what Ask read to give it (from the lookups the server
 * reported while it answered; a conversation opened again later no longer
 * has them), and that it changed nothing, since its tools only read.
 */
export function AskReadOnly({ tools, onNavigate, proposal }: { tools?: string[]; onNavigate?: () => void; proposal?: AskProposal }) {
  const reads = tools ? lookedAt(tools) : [];
  return (
    <div className="ask-ran small">
      {reads.length > 0 && (
        <details className="ask-ran-reads">
          <summary>What Ask looked at ({reads.length})</summary>
          <ul>
            {reads.map((r) => (
              <li key={r.label}>
                {r.to ? (
                  <Link to={r.to} onClick={onNavigate}>
                    {r.label}
                  </Link>
                ) : (
                  r.label
                )}
                {r.count > 1 && <span className="muted"> ×{r.count}</span>}
              </li>
            ))}
          </ul>
        </details>
      )}
      <p className="ask-ran-note muted">
        {tools && reads.length === 0 ? "Answered without looking anything up. " : ""}
        {changedLine(proposal)}
      </p>
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
  /** An answer's sequence number, for feedback. */
  seq?: number;
  /** The lookups Ask reported while it answered (not kept with the conversation). */
  tools?: string[];
  /** Changes this answer proposed, shown as cards under it (askProposal.ts). */
  proposals?: AskProposal[];
}

const REASONS: Record<string, string> = {
  ask_disabled: "An administrator of this organisation has turned Ask Stackurity off. Admins can turn it on under Integrations → AI assistants.",
  plan_required: "Ask Stackurity is not included in this organisation's plan.",
  read_only: "Ask Stackurity is off while the organisation is read-only.",
  spend_cap: "This organisation's Ask Stackurity budget for the month is used up. It is back on the 1st.",
};

/** The panel: on every page, opened from the top bar. */
/**
 * The panel, mounted once in the app shell (Layout): it stays open, with its
 * conversation, scroll position, half-typed question and any answer still
 * streaming, while the person moves between pages. Open, minimised, the
 * conversation and the question are also kept for the tab (askState.ts),
 * so a reload brings them back. Minimised, it is a small button in the
 * corner, so the page behind can be used (on a phone the panel fills the
 * screen).
 */
export function AskPanel({
  state,
  update,
  status,
  reload,
}: {
  state: AskPanelState;
  update: (patch: Partial<AskPanelState>) => void;
  status: AskStatus | undefined;
  reload: () => void;
}) {
  const { pathname } = useLocation();
  const open = state.open && !state.minimised;
  const conv = state.conversation;
  const text = state.text;
  const setConv = (id: number | null) => update({ conversation: id });
  const setText = (t: string) => update({ text: t });
  const onClose = () => update({ open: false, minimised: false });
  const minimise = () => update({ minimised: true });
  const [convs, setConvs] = useState<AskConversation[]>([]);
  const [turns, setTurns] = useState<Turn[]>([]);
  const [loaded, setLoaded] = useState<number | null>(null);
  const [draft, setDraft] = useState("");
  const [tool, setTool] = useState("");
  const [busy, setBusy] = useState(false);
  // The panel's three views; the tab of the one shown is underlined.
  const [view, setView] = useState<"chat" | "history" | "feedback">("chat");
  const history = view === "history";
  const [fbSent, setFbSent] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [usePage, setUsePage] = useState(true);
  const [longChat, setLongChat] = useState(false);
  const abort = useRef<AbortController | null>(null);
  const input = useRef<HTMLTextAreaElement>(null);
  const end = useRef<HTMLDivElement>(null);
  const body = useRef<HTMLDivElement>(null);
  const scroll = useRef<number | null>(null);
  const page: AskPage | null = pageOf(pathname);
  const secretTyped = looksLikeSecret(text);
  const { project, projects, choose } = useProject();
  const projectName = (id: number | null) => (id ? projects.find((p) => p.id === id)?.name ?? "" : "");

  useEffect(() => setUsePage(true), [pathname]);
  useEffect(() => {
    if (open) end.current?.scrollIntoView({ block: "end" });
  }, [turns, draft, tool]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (!open) return;
    input.current?.focus();
    api.get<{ items: AskConversation[] }>("/ask/conversations").then((r) => setConvs(r.items), () => undefined);
  }, [open]);
  // Hidden and shown again (minimised, closed, Alt+K): the log comes back
  // where the person left it.
  useLayoutEffect(() => {
    if (open && body.current && scroll.current !== null) body.current.scrollTop = scroll.current;
  }, [open]);
  // After a reload, the saved conversation is read back once.
  useEffect(() => {
    if (conv === null || loaded === conv || busy) return;
    setLoaded(conv);
    if (turns.length > 0) return; // this tab already holds it
    api.get<{ messages: AskMessage[]; proposals?: AskProposal[] }>(`/ask/conversations/${conv}`).then(
      (r) => setTurns(toTurns(r.messages, r.proposals)),
      () => setConv(null), // deleted or expired: start afresh
    );
  }, [conv]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => () => abort.current?.abort(), []);

  const keepScroll = () => {
    if (body.current) scroll.current = body.current.scrollTop;
  };
  const hide = (minimised: boolean) => {
    keepScroll();
    if (minimised) minimise();
    else onClose();
  };

  if (!state.open) return null;
  if (state.minimised) {
    return (
      <button type="button" className="ask-bubble" onClick={() => update({ minimised: false })} aria-label={busy ? "Show Ask Stackurity (answering)" : "Show Ask Stackurity"}>
        <AskAvatar />
        <span className="ask-bubble-label">Ask Stackurity</span>
        {busy && <span className="ask-bubble-busy" aria-hidden="true" />}
      </button>
    );
  }

  const fail = (e: unknown) => setError(e instanceof ApiError ? e : new ApiError(0, "error", e instanceof Error ? e.message : String(e)));

  const accept = async () => {
    try {
      await api.post("/ask/notice", { version: ASK_NOTICE_VERSION });
      reload();
    } catch (e) {
      fail(e);
    }
  };

  const openConv = async (id: number) => {
    setLongChat(false);
    setView("chat");
    setError(null);
    try {
      const r = await api.get<{ messages: AskMessage[]; proposals?: AskProposal[] }>(`/ask/conversations/${id}`);
      setLoaded(id);
      setConv(id);
      setTurns(toTurns(r.messages, r.proposals));
    } catch (e) {
      fail(e);
    }
  };

  const fresh = () => {
    setLongChat(false);
    setLoaded(null);
    setConv(null);
    setTurns([]);
    setView("chat");
    setError(null);
    input.current?.focus();
  };

  const remove = async (id: number) => {
    if (
      !(await confirmAction({
        title: "Delete this conversation?",
        consequence: "It cannot be brought back.",
        action: "Delete conversation",
        destructive: true,
      }))
    )
      return;
    try {
      await api.del(`/ask/conversations/${id}`);
      setConvs((cs) => cs.filter((c) => c.id !== id));
      if (conv === id) fresh();
    } catch (e) {
      fail(e);
    }
  };

  const removeAll = async () => {
    if (
      !(await confirmAction({
        title: "Delete all your conversations?",
        message: "Every conversation you had in this organisation.",
        consequence: "They cannot be brought back.",
        action: "Delete all my conversations",
        destructive: true,
      }))
    )
      return;
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
        setLoaded(c.id);
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
    let answerSeq = 0;
    const tools: string[] = [];
    let proposals: AskProposal[] = [];
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
            tools.push(String(e.data.tool ?? "Reading"));
            break;
          case "proposal":
            proposals = [...proposals, e.data as unknown as AskProposal];
            break;
          case "proposals_dropped":
            proposals = [];
            break;
          case "secret_removed": {
            // The server took a secret out of the question before it was
            // kept or sent to the model: show the question as kept, and why.
            const kept = String(e.data.text ?? "");
            setTurns((t) => {
              const at = t.map((x) => x.role).lastIndexOf("user");
              const next = at < 0 ? t : t.map((x, i) => (i === at ? { ...x, text: kept } : x));
              return [...next, { role: "notice", text: SECRET_REMOVED_NOTICE }];
            });
            setConvs((cs) => cs.map((c) => (c.id === id ? { ...c, title: kept } : c)));
            break;
          }
          case "done":
            answerSeq = Number(e.data.answer_seq) || 0;
            if (e.data.message) closing = { role: "notice", text: String(e.data.message) };
            if (e.data.long_chat === true) setLongChat(true);
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
      setTurns((t) => [
        ...t,
        ...(answer || proposals.length ? [{ role: "assistant" as const, text: answer, seq: answerSeq || undefined, tools, proposals }] : []),
        ...(closing ? [closing] : []),
      ]);
      reload();
    }
  };

  const stop = () => abort.current?.abort();
  // A card's new state (applied, dismissed, …), kept with its answer.
  const proposalChanged = (p: AskProposal) =>
    setTurns((ts) => ts.map((t) => (t.proposals?.some((x) => x.id === p.id) ? { ...t, proposals: t.proposals.map((x) => (x.id === p.id ? p : x)) } : t)));
  // On a phone the panel covers the page: following a link minimises it,
  // so the page opens in view and the conversation waits in the corner.
  const onLinkClick = () => {
    if (window.matchMedia("(max-width: 700px)").matches) hide(true);
  };
  const s = status;
  const blocked = s && !s.available ? REASONS[s.reason] ?? s.message : "";
  const left =
    s && s.questions_limit !== null && s.questions_limit !== undefined
      ? `${Math.max(0, s.questions_limit - s.questions_used)} of ${s.questions_limit} questions left${s.question_period === "total" ? "" : " this month"}`
      : "";

  return (
    <aside className="ask-panel" role="dialog" aria-modal="false" aria-label="Ask Stackurity" onKeyDown={(e) => e.key === "Escape" && hide(false)}>
      <header className="ask-head">
        <span className="ask-who">
          <AskAvatar />
          <span>
            <strong>Ask Stackurity</strong>
            <span className="ask-bot-tag">AI assistant</span>
          </span>
        </span>
        <span className="ask-head-actions">
          <button type="button" className="btn btn-sm btn-link" onClick={() => hide(true)} aria-label="Minimise" title="Minimise: keeps this conversation">
            –
          </button>
          <button type="button" className="btn btn-sm btn-link" onClick={() => hide(false)} aria-label="Close">
            ✕
          </button>
        </span>
      </header>
      {/* The conversation's actions get a row of their own, so the name is never cut short. */}
      {s?.notice_accepted && (
        <div className="ask-toolbar">
          {/* Chat, History and Feedback are the panel's views; the one shown is underlined. New chat is an action. */}
          <div className="ask-tabs" role="tablist" aria-label="Ask Stackurity">
            {(
              [
                ["chat", "Chat"],
                ["history", `History${convs.length > 0 ? ` (${convs.length})` : ""}`],
                ["feedback", "Feedback"],
              ] as const
            ).map(([v, label]) => (
              <button
                key={v}
                type="button"
                role="tab"
                aria-selected={view === v}
                className={`tab${view === v ? " tab-active" : ""}`}
                onClick={() => {
                  setFbSent(false);
                  setView(v);
                }}
              >
                {label}
              </button>
            ))}
          </div>
          <button type="button" className="btn btn-sm btn-link ask-new" onClick={fresh}>
            + New chat
          </button>
        </div>
      )}
      {s?.notice_accepted && view === "chat" && project && (
        <p className="ask-scope small">
          Answers cover the <strong>{project.name}</strong> project only.{" "}
          <button type="button" className="btn-link" onClick={() => choose(0)}>
            Use all projects
          </button>
        </p>
      )}
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
      ) : view === "feedback" ? (
        <div className="ask-body">
          {fbSent ? (
            <div className="ask-fb-thanks">
              <p>Thanks: your feedback on Ask was sent.</p>
              <button type="button" className="btn btn-sm" onClick={() => setView("chat")}>
                Back to the chat
              </button>
            </div>
          ) : (
            <>
              <AskFeedbackForm conv={conv} seq={null} title="Feedback on Ask" onClose={() => setView("chat")} onSent={() => setFbSent(true)} />
              <p className="small muted ask-fb-other">
                About something else in Stackurity? Use <strong>Send feedback</strong> in your account menu (top right).
              </p>
            </>
          )}
        </div>
      ) : history ? (
        <div className="ask-body">
          {convs.length === 0 ? (
            <p className="muted">No conversations yet. They are deleted 30 days after you start them.</p>
          ) : (
            <>
              <p className="small muted ask-history-note">Your conversations in this organisation. Each is deleted 30 days after you start it.</p>
              {historyGroups(convs, new Date()).map((g) => (
                <section key={g.label} className="ask-history-group">
                  <h4 className="ask-history-day">{g.label}</h4>
                  <ul className="ask-history">
                    {g.items.map((c) => {
                      const where = projectName(c.project_id);
                      return (
                        <li key={c.id} className={c.id === conv ? "ask-history-current" : undefined}>
                          <button type="button" className="ask-history-open" onClick={() => void openConv(c.id)} aria-current={c.id === conv ? "true" : undefined}>
                            <span className="ask-history-title">{c.title || "Untitled"}</span>
                            <span className="ask-history-meta small muted">
                              <RelativeTime iso={c.updated_at} />
                              {where ? ` · ${where} project` : " · All projects"}
                              {c.id === conv ? " · Open now" : ""}
                            </span>
                          </button>
                          <button type="button" className="btn btn-sm btn-link ask-history-delete" onClick={() => void remove(c.id)} aria-label={`Delete ${c.title || "conversation"}`}>
                            Delete
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                </section>
              ))}
              <button type="button" className="btn btn-sm btn-link-danger ask-history-delete-all" onClick={() => void removeAll()}>
                Delete all my conversations
              </button>
            </>
          )}
        </div>
      ) : (
        <>
          <div className="ask-body ask-log" aria-live="polite" ref={body}>
            {turns.length === 0 && !busy && (
              <div className="muted">
                <p>Hi, I&apos;m Ask Stackurity, an AI assistant. Ask me about your inventory, issues and fixes. For example:</p>
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
                <BotTurn key={`${conv ?? "new"}:${i}`}>
                  <AskAnswer text={t.text} onNavigate={onLinkClick} />
                  {conv !== null &&
                    t.proposals?.map((p) => (
                      <AskProposalCard
                        key={p.id}
                        conv={conv}
                        proposal={p}
                        onChange={proposalChanged}
                        onNavigate={onLinkClick}
                        onLeave={() => update({ open: true, minimised: false })}
                      />
                    ))}
                  <AskAnswerExtras text={t.text} onNavigate={onLinkClick} />
                  <AskReadOnly tools={t.tools} onNavigate={onLinkClick} proposal={t.proposals?.[0]} />
                  {conv !== null && t.seq ? <AskRate conv={conv} seq={t.seq} /> : null}
                </BotTurn>
              ) : (
                <p key={i} className="ask-note small">
                  {t.text}
                </p>
              ),
            )}
            {draft && (
              <BotTurn>
                <AskAnswer text={draft} onNavigate={onLinkClick} />
              </BotTurn>
            )}
            {busy && <p className="small muted ask-tool">{tool ? `${tool}…` : "Thinking…"}</p>}
            <div ref={end} />
          </div>
          {longChat && !busy && <AskLongChat onNew={fresh} />}
          <form className="ask-form" onSubmit={(e) => void send(e)}>
            {blocked && (
              <p className="ask-note small">
                <PlaceText text={blocked} />
              </p>
            )}
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
              aria-describedby={secretTyped ? "ask-secret-warning" : undefined}
            />
            {secretTyped && (
              <p id="ask-secret-warning" className="ask-secret-warning small" role="alert">
                {SECRET_TYPING_WARNING}
              </p>
            )}
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
 * Integrations → AI assistants: the organisation admin's switch for Ask
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
  const [consenting, setConsenting] = useState(false);
  const setPropose = (on: boolean) => void run(async () => setS(await api.put<AskSettings>("/ask/settings", { propose_changes: on })));
  // Turning it on goes through the consent dialog; off needs nothing.
  const toggle = (enabled: boolean) => {
    if (enabled) setConsenting(true);
    else void run(async () => setS(await api.put<AskSettings>("/ask/settings", { enabled: false })));
  };
  const consent = () => {
    setConsenting(false);
    void run(async () => setS(await api.put<AskSettings>("/ask/settings", { enabled: true, consent_version: ASK_CONSENT_VERSION })));
  };
  const deleteAll = async () => {
    if (
      !(await confirmAction({
        title: "Delete every Ask Stackurity conversation in this organisation?",
        message: "Whoever had them.",
        consequence: "They cannot be brought back.",
        action: "Delete all conversations",
        destructive: true,
      }))
    )
      return;
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
          {consenting && <AskConsentDialog provider={s.provider} onConsent={consent} onCancel={() => setConsenting(false)} />}
          <CheckCard
            checked={s.propose_changes}
            disabled={busy}
            onChange={setPropose}
            label="Ask may propose changes"
            description="When someone asks for a change (assign, snooze or ignore issues, check again, add assets to a project, rename a project), Ask shows it as a card with Apply and Dismiss. Nothing changes until that person clicks Apply, and only within their own role. When an admin asks to connect something (GitHub, Jira, Slack, a new server and more), the card starts it on the service's own page. Ask never makes a change by itself."
          />
          <p className="small muted">
            {s.questions_this_month} questions this month
            {s.question_limit !== null ? ` of ${s.question_limit}${s.question_period === "total" ? " in total" : ""}` : ""}
            {s.spend_cap_micros !== null ? `, $${(s.spend_this_month_micros / 1e6).toFixed(2)} of a $${(s.spend_cap_micros / 1e6).toFixed(2)} monthly budget` : ""}.
            Model: {s.model}.
          </p>
          <p className="small muted">
            Conversations are kept 30 days. You can delete everyone&apos;s, but not read them.{" "}
            <button type="button" className="btn btn-sm btn-link-danger" disabled={busy} onClick={() => void deleteAll()}>
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
  return provider === "bedrock" ? "Amazon Bedrock" : provider === "vertex" ? "Google Vertex AI" : "Anthropic, PBC, which may process them in the United States or other regions";
}

function toTurns(messages: AskMessage[], proposals: AskProposal[] = []): Turn[] {
  const byAnswer = proposalsByAnswer(messages, proposals);
  return messages.map((m) =>
    m.stop_reason === "refusal" && !m.text
      ? { role: "notice", text: "Claude declined to answer this question." }
      : { role: m.role, text: m.text, seq: m.seq, proposals: byAnswer.get(m.seq) },
  );
}

/** The assistant's avatar: a small robot in the brand colour, so it reads as a bot. */
export function AskAvatar() {
  return (
    <span className="ask-avatar" aria-hidden="true">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="4" y="8" width="16" height="12" rx="3" />
        <path d="M12 4v4" />
        <circle cx="12" cy="3" r="1" />
        <path d="M9 13v1M15 13v1" />
        <path d="M9.5 17h5" />
      </svg>
    </span>
  );
}

/** One answer from the assistant, marked as the bot's. */
function BotTurn({ children }: { children: ReactNode }) {
  return (
    <div className="ask-bot-turn">
      <AskAvatar />
      <div className="ask-bot-msg">
        <span className="ask-bot-name small muted">Ask Stackurity</span>
        {children}
      </div>
    </div>
  );
}

/**
 * The consent an administrator gives before Ask Stackurity is turned on:
 * the approved wording (ask.ts consentText), a box to tick, and Turn on,
 * which stays disabled until the box is ticked. Cancel, Escape or a click
 * outside leaves it off. The server records who agreed, when and to which
 * version (ask.consent in the audit log).
 */
export function AskConsentDialog({ provider, onConsent, onCancel }: { provider: string; onConsent: () => void; onCancel: () => void }) {
  const [agreed, setAgreed] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    box.current?.querySelector<HTMLElement>("input")?.focus();
  }, []);
  return (
    <div className="confirm-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onCancel()}>
      <div
        ref={box}
        className="confirm-dialog ask-consent"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="ask-consent-title"
        aria-describedby="ask-consent-body"
        tabIndex={-1}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.preventDefault();
            onCancel();
          }
        }}
      >
        <h2 id="ask-consent-title" className="confirm-title">
          Turn on Ask Stackurity for this organisation?
        </h2>
        <div id="ask-consent-body" className="confirm-body">
          {consentText(provider, "organisation").map((p, i) => (
            <p key={i}>{p}</p>
          ))}
          <label className="ask-consent-check">
            <input type="checkbox" checked={agreed} onChange={(e) => setAgreed(e.target.checked)} />
            <span>{consentCheckbox(provider)}</span>
          </label>
        </div>
        <div className="confirm-actions">
          <button type="button" className="btn" onClick={onCancel}>
            Cancel
          </button>
          <button type="button" className="btn btn-primary confirm-action" disabled={!agreed} onClick={onConsent}>
            Turn on Ask Stackurity
          </button>
        </div>
      </div>
    </div>
  );
}
