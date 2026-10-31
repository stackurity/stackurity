import type { ReactNode } from "react";
import { Link } from "react-router";
import { CodeBlock } from "../components/ui";
import type { Block } from "./types";

const TOKEN = /(\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\([^)]+\))/g;

/** Inline markup: **bold**, `code`, [label](/path) and [label](help:id). */
export function Inline({ text }: { text: string }) {
  const parts = text.split(TOKEN).filter((x) => x !== "");
  return (
    <>
      {parts.map((part, i) => {
        if (part.startsWith("**") && part.endsWith("**")) return <strong key={i}>{part.slice(2, -2)}</strong>;
        if (part.startsWith("`") && part.endsWith("`")) return <code key={i} className="code">{part.slice(1, -1)}</code>;
        const m = part.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
        if (m) {
          const [, label, href] = m;
          const to = href.startsWith("help:") ? `/help/${href.slice(5)}` : href;
          // Only in-app links are written in articles.
          if (to.startsWith("/")) return <Link key={i} to={to}>{label}</Link>;
          return <span key={i}>{label}</span>;
        }
        return <span key={i}>{part}</span>;
      })}
    </>
  );
}

export function RenderBlock({ b }: { b: Block }): ReactNode {
  if ("p" in b) return <p><Inline text={b.p} /></p>;
  if ("h" in b) return <h3 className="help-h" id={b.id}>{b.h}</h3>;
  if ("steps" in b)
    return (
      <ol className="help-steps">
        {b.steps.map((s, i) => (
          <li key={i}>
            <Inline text={s} />
          </li>
        ))}
      </ol>
    );
  if ("list" in b)
    return (
      <ul className="help-list">
        {b.list.map((s, i) => (
          <li key={i}>
            <Inline text={s} />
          </li>
        ))}
      </ul>
    );
  if ("code" in b) return <CodeBlock label={b.label ?? "Example"} text={b.code} />;
  if ("note" in b)
    return (
      <div className="alert alert-info help-callout">
        <Inline text={b.note} />
      </div>
    );
  if ("warn" in b)
    return (
      <div className="alert alert-warn help-callout">
        <Inline text={b.warn} />
      </div>
    );
  const [head, ...rows] = b.table;
  return (
    <div className="table-wrap help-table">
      <table className="table">
        <thead>
          <tr>
            {head.map((h, i) => (
              <th key={i} scope="col">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              {r.map((c, j) => (
                <td key={j}>
                  <Inline text={c} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
