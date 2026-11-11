import { Link } from "react-router";
import { IconFilter, IconHelp, IconInbox } from "./Icons";
import { useEffect, useState, type MouseEvent, type ReactNode } from "react";
import { ApiError } from "../api";
import type { JobState } from "../hooks";
import type { Tone } from "./Badge";
import { absTime, relTime } from "../format";
import { errorView } from "../errors";
import type { EmptyActionCopy } from "../emptyCopy";
import { reportShownError } from "../clientErrors";
import { useRoutePattern } from "./ErrorReports";

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

/**
 * An error in plain words (errors.ts): the status and code are kept for
 * support behind a toggle, never in the sentence. What it shows is
 * reported to the server once (clientErrors.ts): the route pattern, the
 * API call, status and code, never the page's data.
 */
export function ErrorBox({ error, title }: { error: ApiError | null | undefined; title?: string }) {
  const where = useRoutePattern();
  if (!error) return null;
  reportShownError(error, where.route, where.inApp);
  const v = errorView(error);
  return (
    <div className="alert alert-error" role="alert">
      <strong>{title ?? "Something went wrong"}:</strong> {v.text}
      {v.support && (
        <details className="error-support">
          <summary>Details for support</summary>
          <code>{v.support}</code>
        </details>
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

export interface EmptyAction extends EmptyActionCopy {
  /** A button on this page (opens a form) instead of a link. */
  onClick?: () => void;
}

/**
 * An empty list: why it is empty (`why`, or children), the one action that
 * fills it, and what appears then (`after`). The action is a button only
 * when the person may use it; otherwise its `otherwise` line says who can.
 * The copy for each page is in emptyCopy.ts.
 */
export function EmptyState({
  title,
  why,
  after,
  action,
  children,
  help,
  helpLabel,
}: {
  title: string;
  why?: ReactNode;
  after?: ReactNode;
  action?: EmptyAction;
  children?: ReactNode;
  help?: string;
  helpLabel?: string;
}) {
  const otherwise = action && !action.permitted ? action.otherwise : undefined;
  return (
    <div className="empty">
      <span className="empty-icon" aria-hidden="true">
        <IconInbox size={24} />
      </span>
      <p className="empty-title">{title}</p>
      {(why || children || after || otherwise) && (
        <div className="empty-body">
          {why && <p>{why}</p>}
          {children}
          {after && <p>{after}</p>}
          {otherwise && <p>{otherwise}</p>}
        </div>
      )}
      {action?.permitted && (
        <p className="empty-action">
          {action.to ? (
            <Link className="btn btn-primary" to={action.to}>
              {action.label}
            </Link>
          ) : (
            <button type="button" className="btn btn-primary" onClick={action.onClick}>
              {action.label}
            </button>
          )}
        </p>
      )}
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
      <StackLoader />
      {label}
    </p>
  );
}

/** The logo's three layers, stacked and breathing (styles.css .stack-loader). */
export function StackLoader() {
  return (
    <span className="stack-loader" aria-hidden="true">
      {["l1", "l2", "l3"].map((l) => (
        <span key={l} className={`stack-loader-layer ${l}`}>
          <i />
          <i />
          <i />
          <i />
        </span>
      ))}
    </span>
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
  unit,
  onChange,
}: {
  total: number;
  limit: number;
  offset: number;
  /** What is paged when it is not the rows themselves, e.g. "assets". */
  unit?: string;
  onChange: (offset: number) => void;
}) {
  if (total === 0) return null;
  const from = offset + 1;
  const to = Math.min(offset + limit, total);
  // The pager sits under the list. Without this the window stays at the
  // bottom after a page change, where the new page can look like the old one
  // (an asset with hundreds of similar kernel CVEs, grouped by asset).
  const go = (e: MouseEvent<HTMLButtonElement>, next: number) => {
    onChange(next);
    const list = e.currentTarget.closest("nav")?.parentElement;
    if (list && list.getBoundingClientRect().top < 0) list.scrollIntoView({ block: "start" });
  };
  return (
    <nav className="pager" aria-label="Pagination">
      <span className="muted">
        {from.toLocaleString()}–{to.toLocaleString()} of {total.toLocaleString()}
        {unit ? ` ${unit}` : ""}
      </span>
      <button type="button" className="btn btn-sm" disabled={offset <= 0} onClick={(e) => go(e, Math.max(0, offset - limit))}>
        Previous
      </button>
      <button type="button" className="btn btn-sm" disabled={to >= total} onClick={(e) => go(e, offset + limit)}>
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
  idPrefix = "",
}: {
  tabs: { id: T; label: ReactNode }[];
  value: T;
  onChange: (id: T) => void;
  label: string;
  /** Prefixes the tab and panel ids, for a page with more than one set of tabs. */
  idPrefix?: string;
}) {
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          role="tab"
          id={`${idPrefix}tab-${t.id}`}
          aria-selected={t.id === value}
          aria-controls={`${idPrefix}panel-${t.id}`}
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

/**
 * A card. `description` says in one plain sentence what this card is for,
 * under the title, so someone new can tell what they would change here.
 */
export function Card({
  title,
  description,
  actions,
  children,
  id,
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  id?: string;
}) {
  return (
    <section className="card" id={id}>
      {(title || actions) && (
        <header className={`card-head${description ? " card-head-desc" : ""}`}>
          <div className="card-head-text">
            {title && <h2>{title}</h2>}
            {description && <p className="card-desc">{description}</p>}
          </div>
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

/**
 * A card that opens and closes (native <details>, so it works by keyboard
 * and find-in-page). The summary shows the title, a one-line description
 * and any badges, so a closed card still says what is inside. `forceOpen`
 * opens it (a link to its id); the person can close it again.
 */
export function DisclosureCard({
  id,
  title,
  description,
  badges,
  defaultOpen = false,
  forceOpen = false,
  children,
}: {
  id: string;
  title: ReactNode;
  description?: ReactNode;
  badges?: ReactNode;
  defaultOpen?: boolean;
  forceOpen?: boolean;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen || forceOpen);
  useEffect(() => {
    if (forceOpen) setOpen(true);
  }, [forceOpen]);
  return (
    <details className="card disclosure" id={id} open={open} onToggle={(e) => setOpen(e.currentTarget.open)}>
      <summary className="card-head card-head-desc">
        <div className="card-head-text">
          <h2>
            {title}
            {badges && <span className="badges disclosure-badges">{badges}</span>}
          </h2>
          {description && <p className="card-desc">{description}</p>}
        </div>
      </summary>
      <div className="disclosure-body">{children}</div>
    </details>
  );
}

/*
 * Settings layout (see web/UI-PATTERNS.md). A settings card is a stack of
 * SettingRows: what the setting is and what it is for on the left, its
 * control on the right (stacked on phones), with a line between rows. Choices
 * are ChoiceCards: the option's name on one line, what it means under it.
 * What the current setting means for people now, and Save, go in CardFooter.
 */

/** One setting: its name and purpose beside (or above) its control. */
export function SettingRow({
  title,
  description,
  children,
  id,
  badge,
}: {
  title: ReactNode;
  /** What this setting is for, in plain words; the effect of changing it. */
  description?: ReactNode;
  children: ReactNode;
  id?: string;
  /** A plan or state badge shown beside the title. */
  badge?: ReactNode;
}) {
  return (
    <div className="setting-row" id={id}>
      <div className="setting-row-text">
        <h3 className="setting-row-title">
          {title}
          {badge}
        </h3>
        {description && <div className="setting-row-desc">{description}</div>}
      </div>
      <div className="setting-row-control">{children}</div>
    </div>
  );
}

/** A titled group of related fields inside a card (e.g. "Base scores"). */
export function FieldGroup({ title, description, children }: { title: ReactNode; description?: ReactNode; children: ReactNode }) {
  return (
    <fieldset className="field-group">
      <legend className="field-group-title">{title}</legend>
      {description && <p className="field-group-desc">{description}</p>}
      {children}
    </fieldset>
  );
}

export interface ChoiceOption<T extends string> {
  value: T;
  label: ReactNode;
  /** What picking this means, on its own line under the label. */
  description?: ReactNode;
  /** e.g. "Recommended" or a plan badge, beside the label. */
  badge?: ReactNode;
  disabled?: boolean;
}

/**
 * Radio choices as cards: the label on top, its meaning under it. Use for
 * any pick-one setting with more than two options or options that need a word
 * of explanation.
 */
export function ChoiceCards<T extends string>({
  name,
  options,
  value,
  onChange,
  legend,
  describedBy,
  columns,
}: {
  name: string;
  options: ChoiceOption<T>[];
  value: T;
  onChange: (v: T) => void;
  /** Visually hidden label for the group when the SettingRow title already says it. */
  legend: string;
  describedBy?: string;
  /** Lay the cards side by side (2 or 3) on wide screens. */
  columns?: 2 | 3;
}) {
  return (
    <fieldset className="choice-cards-set">
      <legend className="sr-only">{legend}</legend>
      <div className={`choice-cards${columns ? ` choice-cards-${columns}` : ""}`}>
        {options.map((o) => (
          <label key={o.value} className={`choice-card${o.disabled ? " choice-card-disabled" : ""}`}>
            <input
              type="radio"
              name={name}
              checked={value === o.value}
              disabled={o.disabled}
              aria-describedby={describedBy}
              onChange={() => onChange(o.value)}
            />
            <span className="choice-card-text">
              <span className="choice-card-label">
                {o.label}
                {o.badge}
              </span>
              {o.description && <span className="choice-card-desc">{o.description}</span>}
            </span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

/** A checkbox with a label and a line saying what ticking it does. */
export function CheckCard({
  checked,
  onChange,
  label,
  description,
  disabled,
  badge,
}: {
  checked: boolean;
  onChange: (on: boolean) => void;
  label: ReactNode;
  description?: ReactNode;
  disabled?: boolean;
  badge?: ReactNode;
}) {
  return (
    <label className={`choice-card${disabled ? " choice-card-disabled" : ""}`}>
      <input type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span className="choice-card-text">
        <span className="choice-card-label">
          {label}
          {badge}
        </span>
        {description && <span className="choice-card-desc">{description}</span>}
      </span>
    </label>
  );
}

/** Small "Recommended" style badge for a ChoiceCards option. */
export function OptionBadge({ children, tone = "info" }: { children: ReactNode; tone?: "info" | "good" | "muted" }) {
  return <span className={`option-badge option-badge-${tone}`}>{children}</span>;
}

/**
 * The bottom strip of a settings card: what the current choice means for
 * people right now (status), and the card's Save.
 */
export function CardFooter({ status, children }: { status?: ReactNode; children?: ReactNode }) {
  return (
    <div className="card-footer">
      {status && (
        <div className="card-footer-status small" role="status">
          {status}
        </div>
      )}
      {children && <div className="form-actions card-footer-actions">{children}</div>}
    </div>
  );
}

/** Side notes a newcomer needs but that do not change a setting. */
export function GoodToKnow({ children, title = "Good to know" }: { children: ReactNode; title?: string }) {
  return (
    <aside className="good-to-know">
      <p className="good-to-know-title">{title}</p>
      <div className="good-to-know-body">{children}</div>
    </aside>
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
/** A secret as it is shown until revealed: its first characters (the same prefix lists show), then dots. */
export function maskSecret(secret: string): string {
  return `${secret.slice(0, Math.min(8, Math.floor(secret.length / 3)))}••••••••••••`;
}

/**
 * A command to copy. With `secret`, that part of the text is masked on screen
 * until "Show" is pressed (screen shares and screenshots do not leak it);
 * Copy always copies the real text.
 */
export function CodeBlock({ text, label, secret }: { text: string; label: string; secret?: string }) {
  const [copied, setCopied] = useState(false);
  const [shown, setShown] = useState(false);
  const masked = !!secret && !shown;
  const display = masked ? text.split(secret!).join(maskSecret(secret!)) : text;
  return (
    <div className="codeblock">
      <pre className="mono small" aria-label={label} tabIndex={0}>
        {display}
      </pre>
      <div className="codeblock-actions">
      {secret && (
        <button type="button" className="btn btn-sm" aria-pressed={shown} onClick={() => setShown((v) => !v)}>
          {shown ? "Hide code" : "Show code"}
          <span className="sr-only"> in {label}</span>
        </button>
      )}
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
    </div>
  );
}

/**
 * Filters behind one "Filters" button: a panel under the button on wide
 * screens, a bottom sheet on phones. Preset chips stay outside it so the
 * common choices are one tap away.
 */
export function FilterPanel({ active, children, onClear }: { active: number; children: ReactNode; onClear?: () => void }) {
  const [open, setOpen] = useState(false);
  const [id] = useState(() => `fp${Math.random().toString(36).slice(2, 8)}`);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open]);
  return (
    <div className="filter-bar">
      <button type="button" className="btn filter-toggle" aria-expanded={open} aria-controls={id} onClick={() => setOpen(!open)}>
        <IconFilter size={16} /> Filters
        {active > 0 && (
          <span className="filter-count">
            {active}
            <span className="sr-only"> active</span>
          </span>
        )}
      </button>
      {active > 0 && onClear && (
        <button type="button" className="btn btn-link" onClick={onClear}>
          Clear filters
        </button>
      )}
      {open && <div className="filter-backdrop" aria-hidden="true" onClick={() => setOpen(false)} />}
      <div id={id} className={`filter-panel${open ? " open" : ""}`} hidden={!open} role="group" aria-label="Filters">
        <div className="filter-panel-head">
          <strong>Filters</strong>
          <button type="button" className="btn btn-sm" onClick={() => setOpen(false)}>
            Done
          </button>
        </div>
        <form className="filters" role="search" onSubmit={(e) => e.preventDefault()}>
          {children}
        </form>
      </div>
    </div>
  );
}

/** A row of preset filters; each chip is a link so it can be shared. */
export function PresetChips({ label, chips }: { label: string; chips: { to: string; label: ReactNode; active: boolean }[] }) {
  return (
    <nav className="preset-chips" aria-label={label}>
      {chips.map((c, i) => (
        <Link key={i} to={c.to} className={`preset-chip${c.active ? " active" : ""}`} aria-current={c.active ? "true" : undefined}>
          {c.label}
        </Link>
      ))}
    </nav>
  );
}

/**
 * The one Save of a settings page, at the end of its form: sticky at the
 * bottom of the window while something is unsaved, disabled otherwise.
 */
export function SaveBar({
  dirty,
  pending,
  saved,
  onDiscard,
  label = "Save changes",
}: {
  dirty: boolean;
  pending: boolean;
  /** Just saved: says so until the next change. */
  saved?: boolean;
  onDiscard?: () => void;
  label?: string;
}) {
  return (
    <div className={`save-bar${dirty ? " save-bar-dirty" : ""}`}>
      <span className="save-bar-state small" role="status" aria-live="polite">
        {dirty ? "You have unsaved changes." : saved ? "Saved." : ""}
      </span>
      <div className="form-actions">
        {dirty && onDiscard && (
          <button type="button" className="btn" onClick={onDiscard} disabled={pending}>
            Discard
          </button>
        )}
        <button type="submit" className="btn btn-primary" disabled={!dirty || pending}>
          {pending ? "Saving…" : label}
        </button>
      </div>
    </div>
  );
}
