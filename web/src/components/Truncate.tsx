import { useState, type MouseEvent } from "react";
import { Link } from "react-router";
import { truncateParts } from "../truncate";
import { IconCopy } from "./Icons";

/**
 * A long name or package identifier in a table cell: it is cut with an
 * ellipsis in the middle when the column is narrow, keeping the end that
 * tells rows apart (a version, a file name). The full value is the hover
 * title, is shown whole while the link has keyboard focus, and can be
 * copied with the button beside it. Short values render as they are.
 */
export function TruncatedName({
  value,
  to,
  className,
  copy = true,
}: {
  value: string;
  /** Makes the name a link. */
  to?: string;
  className?: string;
  /** Show a copy button (default). */
  copy?: boolean;
}) {
  const { head, tail } = truncateParts(value);
  const text = (
    <>
      <span className="trunc-head">{head}</span>
      {tail && <span className="trunc-tail">{tail}</span>}
    </>
  );
  const cls = ["trunc-text", className].filter(Boolean).join(" ");
  return (
    <span className="trunc">
      {to ? (
        <Link to={to} className={cls} title={value}>
          {text}
        </Link>
      ) : (
        <span className={cls} title={value} tabIndex={0}>
          {text}
        </span>
      )}
      {copy && <CopyValue value={value} />}
    </span>
  );
}

/** A small copy button for a value in a table. Says "Copied" for two seconds. */
export function CopyValue({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  const run = async (e: MouseEvent) => {
    // A row may open on click; copying must not.
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };
  return (
    <button type="button" className="copy-value" onClick={(e) => void run(e)} aria-label={copied ? "Copied" : `Copy ${value}`} title={copied ? "Copied" : "Copy"}>
      {copied ? <span className="copy-value-done small">Copied</span> : <IconCopy size={14} />}
    </button>
  );
}
