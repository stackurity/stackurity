import type { ReactNode } from "react";
import { Link } from "react-router";
import type { FindingWhy, SecondCheck } from "../api";
import { Badge, type Tone } from "./Badge";
import { KeyValues, RelativeTime } from "./ui";

const STATE_TONE: Record<string, Tone> = { confirmed: "good", needs_validation: "warn", stale: "warn", rejected: "muted" };

const CHECK_LABEL: Record<string, [string, Tone]> = {
  agreed: ["second check agreed", "good"],
  disagreed: ["second check disagreed", "crit"],
  could_not_check: ["second check could not check", "muted"],
};

export function SecondCheckBadge({ check }: { check: SecondCheck | null | undefined }) {
  if (!check) return null;
  const [label, tone] = CHECK_LABEL[check.result] ?? [check.result, "muted"];
  return <Badge status={`second-check-${check.result}`} tone={tone} label={label} title={check.reason || undefined} />;
}

/**
 * Why this finding matched, in one sentence, with its evidence state, what
 * is missing and the independent second check. Leads the finding page.
 */
export function WhyMatched({ why }: { why: FindingWhy }) {
  const check = why.second_check;
  const state = why.evidence_state.replace(/_/g, " ");
  return (
    <section className="card why" aria-labelledby="why-title">
      <header className="card-head">
        <h2 id="why-title">Why it matched</h2>
      </header>
      <p className="why-sentence break">{why.sentence}</p>
      <p className="badges">
        <Badge status={why.evidence_state} tone={STATE_TONE[why.evidence_state] ?? "muted"} label={`Evidence: ${state}`} />
        {why.needs_review ? (
          <Badge status="second-check-disagreed" tone="warn" label="Needs validation: second check disagreed" />
        ) : (
          <SecondCheckBadge check={check} />
        )}
      </p>
      <p className="small">{why.evidence_state_text}</p>
      {why.missing_information.length > 0 && (
        <div className="alert alert-warn" role="note">
          <strong>Missing information</strong>
          <ul className="ref-list">
            {why.missing_information.map((m, i) => (
              <li key={i} className="break">
                {m}
              </li>
            ))}
          </ul>
        </div>
      )}
      <p className="small break">
        <strong>Second check:</strong> {why.second_check_text}{" "}
        <Link to="/help/how-stackurity-knows">How Stackurity knows</Link>
      </p>
      {check && check.differences.length > 0 && (
        <ul className="ref-list small">
          {check.differences.map((d, i) => (
            <li key={i} className="break">
              <strong>{d.field.replace(/_/g, " ")}:</strong> matcher says <span className="mono">{d.matcher}</span>, second check
              finds <span className="mono">{d.independent}</span>
              {d.note ? ` (${d.note})` : ""}
            </li>
          ))}
        </ul>
      )}
      <details>
        <summary>The evidence behind the sentence</summary>
        <KeyValues
          entries={[
            ["installed version", <span className="mono break">{why.installed.version || "unknown"}</span>],
            ...(why.installed.compared
              ? ([["compared as", <span className="mono break">{why.installed.compared}</span>]] as [string, ReactNode][])
              : []),
            ["read from", <span className="break">{why.installed.from}</span>],
            ["collector", why.installed.collector || <span className="muted">unknown</span>],
            ["confidence", why.installed.confidence || <span className="muted">unknown</span>],
            ["observed", <RelativeTime iso={why.installed.observed_at} />],
            ["source", why.source.feed || <span className="muted">unknown</span>],
            ["source refreshed", why.source.refreshed_at ? <RelativeTime iso={why.source.refreshed_at} /> : <span className="muted">never</span>],
            ...(why.source.record ? ([["deciding record", <span className="mono">{why.source.record}</span>]] as [string, ReactNode][]) : []),
            ["rule", <span className="break">{why.rule.text}</span>],
            ...(why.rule.ambiguous?.length
              ? ([["second check asked because", why.rule.ambiguous.map((a) => a.replace(/_/g, " ")).join(", ")]] as [string, ReactNode][])
              : []),
          ]}
        />
      </details>
    </section>
  );
}
