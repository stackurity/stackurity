import type { ReactNode } from "react";

/*
 * A small Markdown renderer for release notes. It builds React elements only
 * (never HTML strings), so raw HTML in the source shows as text. Supported:
 * headings, paragraphs, bullet and numbered lists (nested by indentation),
 * fenced code, block quotes, rules, and inline `code`, **bold**, *emphasis*,
 * [links](https://...) and bare https:// links. Links go to http(s) URLs
 * only and open in a new tab.
 */

const INLINE = /(`[^`\n]+`|\*\*[^*\n]+\*\*|\[[^\]\n]+\]\([^)\s]+\)|https?:\/\/[^\s<>()]+|\*[^*\s][^*\n]*\*)/g;

function safeHref(href: string): string | null {
  try {
    const u = new URL(href);
    return u.protocol === "https:" || u.protocol === "http:" ? u.href : null;
  } catch {
    return null;
  }
}

function ExtLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer">
      {children}
    </a>
  );
}

export function MdInline({ text }: { text: string }) {
  const parts = text.split(INLINE).filter((x) => x !== "");
  return (
    <>
      {parts.map((p, i) => {
        if (p.length > 2 && p.startsWith("`") && p.endsWith("`")) return <code key={i} className="code">{p.slice(1, -1)}</code>;
        if (p.length > 4 && p.startsWith("**") && p.endsWith("**")) return <strong key={i}><MdInline text={p.slice(2, -2)} /></strong>;
        const link = p.match(/^\[([^\]]+)\]\(([^)\s]+)\)$/);
        if (link) {
          const href = safeHref(link[2]);
          return href ? <ExtLink key={i} href={href}><MdInline text={link[1]} /></ExtLink> : <span key={i}>{link[1]}</span>;
        }
        if (/^https?:\/\//.test(p)) {
          // Trailing punctuation belongs to the sentence, not the URL.
          const m = p.match(/^(.*?)([.,;:!?]*)$/) as RegExpMatchArray;
          const href = safeHref(m[1]);
          return href ? (
            <span key={i}>
              <ExtLink href={href}>{m[1]}</ExtLink>
              {m[2]}
            </span>
          ) : (
            <span key={i}>{p}</span>
          );
        }
        if (p.length > 2 && p.startsWith("*") && p.endsWith("*")) return <em key={i}><MdInline text={p.slice(1, -1)} /></em>;
        return <span key={i}>{p}</span>;
      })}
    </>
  );
}

type ListItem = { text: string; children: ListBlock | null };
type ListBlock = { ordered: boolean; items: ListItem[] };
type Block =
  | { kind: "h"; level: number; text: string }
  | { kind: "p"; text: string }
  | { kind: "code"; text: string }
  | { kind: "quote"; text: string }
  | { kind: "hr" }
  | { kind: "list"; list: ListBlock };

const LIST_ITEM = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/;

/** Parses list lines (already known to start a list) into a nested list. */
function parseList(lines: { indent: number; ordered: boolean; text: string }[]): ListBlock {
  const root: ListBlock = { ordered: lines[0].ordered, items: [] };
  const stack: { indent: number; list: ListBlock }[] = [{ indent: lines[0].indent, list: root }];
  for (const l of lines) {
    while (stack.length > 1 && l.indent < stack[stack.length - 1].indent) stack.pop();
    const top = stack[stack.length - 1];
    if (l.indent > top.indent && top.list.items.length > 0 && stack.length < 4) {
      const parent = top.list.items[top.list.items.length - 1];
      const child: ListBlock = { ordered: l.ordered, items: [] };
      parent.children = child;
      stack.push({ indent: l.indent, list: child });
    }
    stack[stack.length - 1].list.items.push({ text: l.text, children: null });
  }
  return root;
}

export function parseMarkdown(src: string): Block[] {
  const lines = src.replace(/\r\n?/g, "\n").split("\n");
  const out: Block[] = [];
  let para: string[] = [];
  const flush = () => {
    if (para.length) out.push({ kind: "p", text: para.join(" ") });
    para = [];
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed.startsWith("```")) {
      flush();
      const code: string[] = [];
      for (i++; i < lines.length && !lines[i].trim().startsWith("```"); i++) code.push(lines[i]);
      out.push({ kind: "code", text: code.join("\n") });
      continue;
    }
    if (trimmed === "") {
      flush();
      continue;
    }
    const h = trimmed.match(/^(#{1,6})\s+(.*?)\s*#*$/);
    if (h) {
      flush();
      out.push({ kind: "h", level: h[1].length, text: h[2] });
      continue;
    }
    if (/^([-*_])(\s*\1){2,}$/.test(trimmed)) {
      flush();
      out.push({ kind: "hr" });
      continue;
    }
    if (trimmed.startsWith(">")) {
      flush();
      const q: string[] = [];
      for (; i < lines.length && lines[i].trim().startsWith(">"); i++) q.push(lines[i].trim().replace(/^>\s?/, ""));
      i--;
      out.push({ kind: "quote", text: q.join(" ") });
      continue;
    }
    if (LIST_ITEM.test(line)) {
      flush();
      const items: { indent: number; ordered: boolean; text: string }[] = [];
      for (; i < lines.length; i++) {
        const m = lines[i].match(LIST_ITEM);
        if (m) {
          const indent = m[1].replace(/\t/g, "  ").length;
          const ordered = /\d/.test(m[2]);
          // A numbered list right after a bullet list (or the reverse) is a new list.
          if (items.length && indent <= items[0].indent && ordered !== items[0].ordered) break;
          items.push({ indent, ordered, text: m[3] });
        } else if (lines[i].trim() !== "" && /^\s+/.test(lines[i]) && items.length) {
          // A wrapped continuation line of the previous item.
          items[items.length - 1].text += " " + lines[i].trim();
        } else {
          break;
        }
      }
      i--;
      out.push({ kind: "list", list: parseList(items) });
      continue;
    }
    para.push(trimmed);
  }
  flush();
  return out;
}

function List({ list }: { list: ListBlock }) {
  const items = list.items.map((it, i) => (
    <li key={i}>
      <MdInline text={it.text} />
      {it.children && <List list={it.children} />}
    </li>
  ));
  return list.ordered ? <ol>{items}</ol> : <ul>{items}</ul>;
}

/**
 * Renders Markdown safely. Headings are shifted so that a "#" in the source
 * is never larger than the page's own section headings (h3 and below).
 */
export function Markdown({ source }: { source: string }) {
  const blocks = parseMarkdown(source);
  return (
    <div className="md">
      {blocks.map((b, i) => {
        switch (b.kind) {
          case "h": {
            const level = Math.min(6, Math.max(3, b.level + 1));
            const Tag = `h${level}` as "h3" | "h4" | "h5" | "h6";
            return (
              <Tag key={i} className="md-h">
                <MdInline text={b.text} />
              </Tag>
            );
          }
          case "p":
            return (
              <p key={i}>
                <MdInline text={b.text} />
              </p>
            );
          case "code":
            return (
              <pre key={i} className="md-code">
                <code>{b.text}</code>
              </pre>
            );
          case "quote":
            return (
              <blockquote key={i}>
                <MdInline text={b.text} />
              </blockquote>
            );
          case "hr":
            return <hr key={i} />;
          case "list":
            return <List key={i} list={b.list} />;
        }
      })}
    </div>
  );
}
