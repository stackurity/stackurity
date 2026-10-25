import { Link } from "react-router";
import { IconHelp, IconInbox } from "./Icons";
import { useEffect, useState, type ReactNode } from "react";
import { ApiError } from "../api";
import type { JobState } from "../hooks";
import type { Tone } from "./Badge";
import { absTime, relTime } from "../format";

export function RelativeTime({ iso, empty = "never" }: { iso: string | null | undefined; empty?: string }) {
  // Re-render every minute so "x min ago" stays honest on an open page.
  const [, setNow] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setNow((n) => n + 1), 60_000);
    return () => clearInterval(t);
  }, []);
  if (!iso) return <span className="muted">{empty}</span>;
  return (
    <time dateTime={iso} title={absTime(iso)}>
      {relTime(iso)}
    </time>
  );
}

export function ErrorBox({ error, title }: { error: ApiError | null | undefined; title?: string }) {
  if (!error) return null;
  return (
    <div className="alert alert-error" role="alert">
      <strong>{title ?? "Error"}:</strong> {error.message}
      {error.code && error.status > 0 && (
        <span className="muted small"> ({error.status} {error.code})</span>
      )}
      {error.details.length > 0 && (
        <ul>
          {error.details.map((d, i) => (
            <li key={i}>{d}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function Notice({ kind = "info", children }: { kind?: "info" | "warn" | "success"; children: ReactNode }) {
  return (
    <div className={`alert alert-${kind}`} role={kind === "warn" ? "alert" : "status"}>
      {children}
    </div>
  );
}

export function EmptyState({ title, children, help, helpLabel }: { title: string; children?: ReactNode; help?: string; helpLabel?: string }) {
  return (
    <div className="empty">
      <span className="empty-icon" aria-hidden="true">
        <IconInbox size={24} />
      </span>
      <p className="empty-title">{title}</p>
      {children && <div className="empty-body">{children}</div>}
      {help && (
        <p className="empty-help">
          <Link to={`/help/${help}`}>{helpLabel ?? "How this works"}</Link>
        </p>
      )}
    </div>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <p className="loading" role="status">
      {label}
    </p>
  );
}

export function StatTile({
  label,
  value,
  sub,
  tone,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  tone?: "good" | "warn" | "bad" | "muted" | "crit" | "orange";
}) {
  return (
    <div className={`tile${tone ? ` tile-${tone}` : ""}`}>
      <div className="tile-label">{label}</div>
      <div className="tile-value">{value}</div>
      {sub && <div className="tile-sub">{sub}</div>}
    </div>
  );
}

export interface Bar {
  key: string;
  label: ReactNode;
  value: number;
  tone?: Tone;
}

/** Horizontal bar rows with the number always printed beside the bar. */
export function BarRows({ bars, emptyText = "Nothing to show." }: { bars: Bar[]; emptyText?: string }) {
  if (bars.length === 0) return <p className="muted">{emptyText}</p>;
  const max = Math.max(1, ...bars.map((b) => b.value));
  return (
    <ul className="bars">
      {bars.map((b) => (
        <li key={b.key} className="bar-row">
          <span className="bar-label">{b.label}</span>
          <span className="bar-track" aria-hidden="true">
            {b.value > 0 && <span className={`bar-fill bar-${b.tone ?? "info"}`} style={{ width: `${(b.value / max) * 100}%` }} />}
          </span>
          <span className="bar-value">{b.value.toLocaleString()}</span>
        </li>
      ))}
    </ul>
  );
}

export function Pager({
  total,
  limit,
  offset,
  onChange,
}: {
  total: number;
  limit: number;
  offset: number;
  onChange: (offset: number) => void;
}) {
  if (total === 0) return null;
  const from = offset + 1;
  const to = Math.min(offset + limit, total);
  return (
    <nav className="pager" aria-label="Pagination">
      <span className="muted">
        {from.toLocaleString()}–{to.toLocaleString()} of {total.toLocaleString()}
      </span>
      <button type="button" className="btn btn-sm" disabled={offset <= 0} onClick={() => onChange(Math.max(0, offset - limit))}>
        Previous
      </button>
      <button type="button" className="btn btn-sm" disabled={to >= total} onClick={() => onChange(offset + limit)}>
        Next
      </button>
    </nav>
  );
}

export function Tabs<T extends string>({
  tabs,
  value,
  onChange,
  label,
}: {
  tabs: { id: T; label: ReactNode }[];
  value: T;
  onChange: (id: T) => void;
  label: string;
}) {
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          role="tab"
          id={`tab-${t.id}`}
          aria-selected={t.id === value}
          aria-controls={`panel-${t.id}`}
          className={`tab${t.id === value ? " tab-active" : ""}`}
          onClick={() => onChange(t.id)}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function KeyValues({ entries }: { entries: [string, ReactNode][] }) {
  if (entries.length === 0) return <p className="muted">None recorded.</p>;
  return (
    <dl className="kv">
      {entries.map(([k, v]) => (
        <div key={k} className="kv-row">
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Card({ title, actions, children }: { title?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="card">
      {(title || actions) && (
        <header className="card-head">
          {title && <h2>{title}</h2>}
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function PageHeader({ title, sub, actions, help }: { title: ReactNode; sub?: ReactNode; actions?: ReactNode; help?: string }) {
  return (
    <header className="page-head">
      <div>
        <h1>
          {title}
          {help && (
            <Link to={`/help/${help}`} className="help-link" title="Help for this page">
              <IconHelp size={16} />
              <span className="sr-only">Help for this page</span>
            </Link>
          )}
        </h1>
        {sub && <p className="page-sub">{sub}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}

export function CopyBox({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };
  return (
    <div className="copybox">
      <label className="sr-only" htmlFor="copybox-value">
        {label}
      </label>
      <input id="copybox-value" readOnly value={value} onFocus={(e) => e.currentTarget.select()} className="mono" />
      <button type="button" className="btn" onClick={copy}>
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}

export function Code({ children }: { children: ReactNode }) {
  return <code className="code">{children}</code>;
}

export function YesNo({ value }: { value: boolean | null | undefined }) {
  if (value === null || value === undefined) return <span className="muted">unknown</span>;
  return <span>{value ? "yes" : "no"}</span>;
}

/** Status line for a background job started with useJobRunner. */
export function JobStatus({ state, onDismiss }: { state: JobState; onDismiss?: () => void }) {
  if (state.phase === "idle") return null;
  const dismiss = onDismiss && state.phase !== "running" && (
    <button type="button" className="btn btn-sm btn-link" onClick={onDismiss}>
      Dismiss
    </button>
  );
  switch (state.phase) {
    case "running":
      return (
        <Notice kind="info">
          <span className="spinner" aria-hidden="true" /> {state.label}: running (job #{state.jobId})…
        </Notice>
      );
    case "done":
      return (
        <Notice kind="success">
          {state.label}: finished. {dismiss}
        </Notice>
      );
    case "already":
      return (
        <Notice kind="info">
          {state.label}: already queued or running. Refresh in a moment. {dismiss}
        </Notice>
      );
    case "timeout":
      return (
        <Notice kind="warn">
          {state.label}: still running after 10 minutes. Check Settings → Jobs. {dismiss}
        </Notice>
      );
    case "failed":
      return (
        <div className="alert alert-error" role="alert">
          <strong>{state.label} failed:</strong> {state.error} {dismiss}
        </div>
      );
  }
}

/** Preformatted, copyable block (setup snippets, config). */
export function CodeBlock({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="codeblock">
      <pre className="mono small" aria-label={label} tabIndex={0}>
        {text}
      </pre>
      <button
        type="button"
        className="btn btn-sm"
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(text);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
          } catch {
            setCopied(false);
          }
        }}
      >
        {copied ? "Copied" : "Copy"}
        <span className="sr-only"> {label}</span>
      </button>
    </div>
  );
}
