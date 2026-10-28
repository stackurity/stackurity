import { useState } from "react";
import {
  api,
  summaryText,
  type DirectoryUser,
  type NotificationOptions,
  type Priority,
  type SendNow,
  type SummaryChoice,
} from "../api";
import { useAction } from "../hooks";
import { SMTP_PRESETS } from "../smtpPresets";
import { ErrorBox } from "./ui";

/*
 * Pieces shared by onboarding (step 5) and Settings, Notifications: the two
 * questions of a route, "Add to Slack", Stackurity's own email recipients and
 * the SMTP provider presets.
 */

export const NOTHING_CHOSEN = "Pick at least one: something right away or a summary.";

/** "Send right away" and "Summary", as two groups of radio buttons. */
export function RouteQuestions({
  idp,
  now,
  summary,
  onChange,
  time,
  day,
  timezone,
  minPriority,
}: {
  idp: string;
  now: SendNow;
  summary: SummaryChoice;
  onChange: (now: SendNow, summary: SummaryChoice) => void;
  time: string;
  day: string;
  timezone: string;
  /** The route's urgent threshold, shown as a note when it is not P1. */
  minPriority?: Priority;
}) {
  const nowOptions: { key: SendNow; label: string; hint?: string }[] = [
    { key: "urgent", label: "Urgent issues", hint: "Exploited, critical, or came back after a fix." },
    { key: "all", label: "All new issues" },
    { key: "none", label: "Nothing right away" },
  ];
  const sumOptions: { key: SummaryChoice; label: string }[] = [
    { key: "daily", label: summaryText("daily", time, day, timezone) },
    { key: "weekly", label: summaryText("weekly", time, day, timezone) },
    { key: "none", label: "No summary" },
  ];
  return (
    <>
      <div className="form-grid">
        <fieldset className="field">
          <legend>Send right away</legend>
          <ul className="choice-list">
            {nowOptions.map((o) => (
              <li key={o.key}>
                <label className="choice">
                  <input type="radio" name={`${idp}-now`} checked={now === o.key} onChange={() => onChange(o.key, summary)} />
                  <span>
                    <strong>{o.label}</strong>
                    {o.hint && <span className="hint"> {o.hint}</span>}
                  </span>
                </label>
              </li>
            ))}
          </ul>
          {now === "urgent" && minPriority && minPriority !== "P1" && minPriority !== "P4" && (
            <p className="hint">Urgent from {minPriority} (see More options).</p>
          )}
        </fieldset>
        <fieldset className="field">
          <legend>Summary</legend>
          <ul className="choice-list">
            {sumOptions.map((o) => (
              <li key={o.key}>
                <label className="choice">
                  <input type="radio" name={`${idp}-sum`} checked={summary === o.key} onChange={() => onChange(now, o.key)} />
                  <span>
                    <strong>{o.label}</strong>
                  </span>
                </label>
              </li>
            ))}
          </ul>
        </fieldset>
      </div>
      {now === "none" && summary === "none" && (
        <div className="alert alert-warn" role="alert">
          {NOTHING_CHOSEN}
        </div>
      )}
    </>
  );
}

/** A primary "Add to Slack" button: asks the server for Slack's address and goes there. */
export function AddToSlackButton({ returnTo, beforeRedirect, disabled }: { returnTo: string; beforeRedirect?: () => void; disabled?: boolean }) {
  const act = useAction();
  const go = async () => {
    beforeRedirect?.();
    const r = await act.run(() => api.post<{ url: string }>("/integrations/slack/install", { return_to: returnTo }));
    if (r?.url) window.location.assign(r.url);
  };
  return (
    <>
      <ErrorBox error={act.error} title="Could not open Slack" />
      <div>
        <button type="button" className="btn btn-primary" onClick={() => void go()} disabled={disabled || act.pending}>
          {act.pending ? "Opening Slack…" : "Add to Slack"}
        </button>
      </div>
    </>
  );
}

/** Splits typed addresses on commas, spaces and new lines. */
export function parseAddresses(s: string): string[] {
  return [...new Set(s.split(/[\s,;]+/).map((x) => x.trim().toLowerCase()).filter(Boolean))];
}

const n = (x: number) => x.toLocaleString("en-US");

export function quotaHint(o: NotificationOptions): string {
  const q = o.platform_email.quota;
  if (!q) return "Messages over the organisation's email limits are added to the next summary.";
  return `Up to ${n(q.per_minute)} emails a minute, ${n(q.per_hour)} an hour, ${n(q.per_day)} a day; extra messages are added to the next summary.`;
}

/** Recipients of an "Email (sent by Stackurity)" channel: members and other addresses. */
export function StackurityEmailFields({
  idp,
  options,
  members,
  userIds,
  setUserIds,
  others,
  setOthers,
}: {
  idp: string;
  options: NotificationOptions;
  members: DirectoryUser[] | undefined;
  userIds: number[];
  setUserIds: (v: number[]) => void;
  others: string;
  setOthers: (v: string) => void;
}) {
  const max = options.platform_email.max_recipients ?? 20;
  const total = userIds.length + parseAddresses(others).length;
  return (
    <>
      <fieldset className="field field-span">
        <legend>Members</legend>
        {!members ? (
          <span className="muted small">Loading…</span>
        ) : members.length === 0 ? (
          <span className="muted small">No members found.</span>
        ) : (
          <div className="checklist">
            {members.map((m) => (
              <label key={m.id} className="check">
                <input
                  type="checkbox"
                  checked={userIds.includes(m.id)}
                  onChange={() => setUserIds(userIds.includes(m.id) ? userIds.filter((x) => x !== m.id) : [...userIds, m.id])}
                />{" "}
                <span className="break">{m.name ? `${m.name} (${m.email})` : m.email}</span>
              </label>
            ))}
          </div>
        )}
        <p className="hint">Members get messages once they have signed in to Stackurity at least once.</p>
      </fieldset>
      <div className="field field-span">
        <label htmlFor={`${idp}-others`}>Other addresses (optional)</label>
        <textarea id={`${idp}-others`} rows={2} value={others} onChange={(e) => setOthers(e.target.value)} placeholder="security@example.com, oncall@example.com" />
        <p className="hint">
          Each address gets an email with a link to confirm, once. Nothing is sent to it until it is confirmed.
        </p>
      </div>
      <p className={`hint field-span${total > max ? " text-bad" : ""}`}>
        {total} of at most {max} recipients. {quotaHint(options)}
        {options.platform_email.from && ` Sent from ${options.platform_email.from}.`}
      </p>
    </>
  );
}

/** "Provider" select that fills host, port, encryption (and username for some). */
export function SmtpProviderPicker({
  idp,
  onApply,
}: {
  idp: string;
  onApply: (v: { host: string; port: number; tls: "starttls" | "tls"; username?: string }) => void;
}) {
  const [id, setId] = useState("");
  const [variant, setVariant] = useState(0);
  const preset = SMTP_PRESETS.find((p) => p.id === id);
  const apply = (pid: string, v: number) => {
    setId(pid);
    setVariant(v);
    const p = SMTP_PRESETS.find((x) => x.id === pid);
    if (!p) return;
    onApply({ host: (p.variants[v] ?? p.variants[0]).host, port: p.port, tls: p.tls, username: p.username });
  };
  return (
    <>
      <div className="field">
        <label htmlFor={`${idp}-provider`}>Provider</label>
        <select id={`${idp}-provider`} value={id} onChange={(e) => apply(e.target.value, 0)}>
          <option value="">Other (type the details)</option>
          {SMTP_PRESETS.map((p) => (
            <option key={p.id} value={p.id}>
              {p.label}
            </option>
          ))}
        </select>
      </div>
      {preset && preset.variants.length > 1 && (
        <div className="field">
          <label htmlFor={`${idp}-variant`}>{preset.variantLabel ?? "Region"}</label>
          <select id={`${idp}-variant`} value={String(variant)} onChange={(e) => apply(preset.id, Number(e.target.value))}>
            {preset.variants.map((v, i) => (
              <option key={v.host} value={String(i)}>
                {v.label}
              </option>
            ))}
          </select>
        </div>
      )}
      {preset && <p className="hint field-span">{preset.note}</p>}
    </>
  );
}
