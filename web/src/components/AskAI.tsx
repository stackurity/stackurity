import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api, type Asset, type AssistantConnection, type FixGroup, type List } from "../api";
import { useAuth } from "../auth";
import { useLoad } from "../hooks";
import { OPEN, askFromAsset, assistantsFor, claudeDesktopLink, readDismissed, writeDismissed, type AskQuestion, type Assistant } from "../askAI";

// One request per page load for "has this person connected an assistant?",
// shared by every banner on the page.
let connections: Promise<AssistantConnection[]> | null = null;
function loadConnections(): Promise<AssistantConnection[]> {
  connections ??= api.getAll<List<AssistantConnection>>("/assistants").then(
    (r) => r.items ?? [],
    () => [], // a token session, or assistants unavailable: treat as not connected
  );
  return connections;
}

const listeners = new Set<() => void>();

/** Whether this person hid the Ask your AI buttons, and a way to change it (shared across the page). */
export function useAskAIHidden(): [boolean, (hidden: boolean) => void] {
  const { me } = useAuth();
  const uid = me?.user?.id;
  const [hidden, setHidden] = useState(() => readDismissed(uid));
  useEffect(() => {
    const f = () => setHidden(readDismissed(uid));
    listeners.add(f);
    f();
    return () => void listeners.delete(f);
  }, [uid]);
  const set = (h: boolean) => {
    writeDismissed(uid, h);
    setHidden(h);
    listeners.forEach((f) => f());
  };
  return [hidden, set];
}

/**
 * "Ask Claude / ChatGPT about this": opens the assistant with a question
 * made of public identifiers only (askAI.ts). Not connected yet: a link to
 * Settings, AI assistants instead. Dismissible per person.
 */
export function AskAI({ question, compact }: { question: AskQuestion | null; compact?: boolean }) {
  const [hidden, setHidden] = useAskAIHidden();
  const [offer, setOffer] = useState<Assistant[] | null>(null);
  const [copied, setCopied] = useState<Assistant | null>(null);

  useEffect(() => {
    if (hidden || !question) return;
    let live = true;
    void loadConnections().then((c) => live && setOffer(assistantsFor(c)));
    return () => {
      live = false;
    };
  }, [hidden, question]);

  if (hidden || !question || offer === null) return null;

  const dismiss = (
    <button type="button" className="btn-link ask-ai-dismiss" onClick={() => setHidden(true)} aria-label="Hide Ask your AI everywhere" title="Hide (you can turn it back on in Settings, AI assistants)">
      ×
    </button>
  );

  if (offer.length === 0) {
    if (compact) return null; // a card in a list: no sales pitch on each one
    return (
      <aside className="ask-ai" aria-label="Ask your AI">
        <span className="ask-ai-text">
          Ask Claude or ChatGPT about this. <Link to="/settings/ai-assistants">Connect your assistant</Link> first, then it can look up the details in
          Stackurity with your permission.
        </span>
        {dismiss}
      </aside>
    );
  }

  // Neither web app documents a prefill parameter: the link opens the app and
  // the click copies the question (started while this page still has focus;
  // a real link, so no popup blocker stands in the way).
  const copy = (a: Assistant) => {
    navigator.clipboard?.writeText(question.text).then(
      () => setCopied(a),
      () => setCopied(null),
    );
  };

  return (
    <aside className={`ask-ai${compact ? " ask-ai-compact" : ""}`} aria-label="Ask your AI">
      {!compact && <span className="ask-ai-text">Ask your assistant about {question.about}:</span>}
      <span className="ask-ai-actions">
        {offer.map((a) => (
          <a key={a} className="btn btn-sm" href={OPEN[a].href} target="_blank" rel="noopener noreferrer" onClick={() => copy(a)} title={question.text}>
            Ask {OPEN[a].label}
            <span className="sr-only"> about {question.about} (opens in a new tab; the question is copied)</span>
          </a>
        ))}
        {offer.includes("claude") && (
          <a className="small" href={claudeDesktopLink(question)} title="Opens Claude Desktop with the question filled in, not sent">
            in Claude Desktop
          </a>
        )}
      </span>
      {copied && (
        <span className="small muted" role="status">
          Question copied: paste it into {OPEN[copied].label}.
        </span>
      )}
      {!compact && (
        <details className="ask-ai-question small">
          <summary>What is sent</summary>
          <p>{question.text}</p>
          <p className="muted">Only public identifiers: no asset names, hostnames, addresses or teams.</p>
        </details>
      )}
      {dismiss}
    </aside>
  );
}

/** The asset page's banner: its OS and the upgrades that need it first, never the asset itself. */
export function AssetAskAI({ asset }: { asset: Asset }) {
  const [hidden] = useAskAIHidden();
  return hidden ? null : <AssetAskAIShown asset={asset} />;
}

function AssetAskAIShown({ asset }: { asset: Asset }) {
  const top = useLoad(() => api.get<List<FixGroup>>("/fix-groups", { asset_id: asset.id, bucket: "focus", limit: 5 }), [asset.id]);
  if (!top.data && !top.error) return null;
  const at = asset.attributes ?? {};
  const os = [at.os_name, at.os === "windows" ? at.os_release : ""].filter(Boolean).join(" ");
  // Every other attribute (hostname, addresses, account, cluster...) counts as internal.
  const internal = Object.entries(at)
    .filter(([k]) => !k.startsWith("os"))
    .map(([, v]) => v);
  const q = askFromAsset({ name: asset.name, os_name: os, environment: asset.environment, internal }, top.data?.items ?? []);
  return <AskAI question={q} />;
}
