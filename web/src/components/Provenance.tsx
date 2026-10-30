import type { ReactNode } from "react";
import { Link } from "react-router";
import { safeHttpUrl, type Advisory, type Finding } from "../api";
import { behindFacts, behindText, isBehind } from "../behind";
import { Badge, type Tone } from "./Badge";
import { Card, RelativeTime } from "./ui";

/** The version rules each comparator family applies (internal/version). */
export const COMPARATOR_LABEL: Record<string, string> = {
  semver: "SemVer",
  composer: "Composer (Packagist) version rules",
  debian: "Debian version rules (dpkg: epoch, upstream version, revision, tilde)",
  rpm: "RPM epoch:version-release",
  apk: "Alpine apk version rules",
  pep440: "PEP 440 (Python)",
  rubygems: "RubyGems version rules",
  maven: "Maven version ordering",
  nuget: "NuGet version rules",
  generic: "Generic dotted-numeric comparison",
};

export function comparatorLabel(c: string | undefined): string {
  if (!c) return "not recorded";
  return COMPARATOR_LABEL[c] ?? c;
}

export interface EvidenceState {
  /** confirmed, needs_validation, stale, stale_intelligence, unknown, rejected */
  state: string;
  label: string;
  tone: Tone;
  /** One line: why the evidence is in this state. */
  explain: string;
}

/**
 * The evidence state of a finding: confirmed, needs validation, stale (the
 * asset stopped reporting, or the advisory data was stale when evaluated) or
 * unknown, with a one-line explanation.
 */
export function evidenceState(f: Finding): EvidenceState {
  const ev = f.evidence ?? {};
  const conf = typeof ev.inventory_conf === "string" && ev.inventory_conf ? ev.inventory_conf : "";
  switch (f.verification) {
    case "confirmed":
      if (ev.feed_stale === true)
        return {
          state: "stale_intelligence",
          label: "confirmed, stale advisory data",
          tone: "warn",
          explain: `The installed version is confirmed, but the ${String(ev.feed ?? "advisory")} feed was stale when this was evaluated, so newer advisory data may change the result.`,
        };
      return {
        state: "confirmed",
        label: "confirmed",
        tone: "good",
        explain:
          f.kind === "end_of_life"
            ? "The installed version was read from an authoritative source and its release line is past its end-of-life date."
            : isBehind(f)
              ? "The installed version was read from an authoritative source and is lower than its release line's latest release."
              : "The installed version was read from an authoritative source (package database or lockfile) and compared with the advisory's ranges. A match is not proof that it can be exploited here.",
      };
    case "needs_validation":
      return {
        state: "needs_validation",
        label: "needs validation",
        tone: "warn",
        explain:
          conf && conf !== "confirmed"
            ? `The installed version is not confirmed (inventory confidence: ${conf}); check the real version on the asset before acting.`
            : "The match cannot be relied on yet: see Missing information above.",
      };
    case "stale":
      return {
        state: "stale",
        label: "stale",
        tone: "warn",
        explain: "The asset has not reported recently: this was true when it was last seen, but may no longer be.",
      };
    case "rejected":
      return { state: "rejected", label: "rejected", tone: "muted", explain: "A person marked this a false positive." };
  }
  return { state: "unknown", label: "unknown", tone: "muted", explain: "The evidence could not be classified: no confirmed version and no recorded source." };
}

export function EvidenceStateBadge({ f }: { f: Finding }) {
  const s = evidenceState(f);
  return <Badge status={s.state} tone={s.tone} label={s.label} title={s.explain} />;
}

function ExtLink({ href, children }: { href: string; children: ReactNode }) {
  const safe = safeHttpUrl(href);
  if (!safe) return <>{children}</>;
  return (
    <a href={safe} target="_blank" rel="noopener noreferrer">
      {children}
      <span className="sr-only"> (opens in a new tab)</span>
    </a>
  );
}

/** Splits evidence.matched_ranges ("ID: range") by advisory id. */
function rangesByAdvisory(ranges: unknown): Map<string, string[]> {
  const out = new Map<string, string[]>();
  if (!Array.isArray(ranges)) return out;
  for (const r of ranges) {
    const s = String(r);
    const i = s.indexOf(": ");
    const id = i > 0 ? s.slice(0, i) : "";
    const range = i > 0 ? s.slice(i + 2) : s;
    out.set(id, [...(out.get(id) ?? []), range]);
  }
  return out;
}

/**
 * Which source, ecosystem, version rule and range produced the verdict, and
 * how far the evidence can be trusted.
 */
export function Provenance({ f, matched }: { f: Finding; matched: Advisory[] }) {
  const ev = f.evidence ?? {};
  const state = evidenceState(f);
  const head = (
    <p>
      <Badge status={state.state} tone={state.tone} label={`Evidence: ${state.label}`} /> {state.explain}
    </p>
  );
  if (f.kind === "end_of_life") {
    return (
      <Card title="How this was decided">
        {head}
        <ul className="ref-list">
          <li>
            Source: <Link to="/intelligence">{String(ev.source ?? "endoflife.date")}</Link>
            {typeof ev.link === "string" && ev.link && (
              <>
                {" "}
                (<ExtLink href={ev.link}>support dates</ExtLink>)
              </>
            )}
          </li>
          <li>
            Release line <span className="mono">{String(ev.cycle ?? "?")}</span> of {String(ev.product ?? f.component_name)}, matched from installed
            version <span className="mono">{f.version}</span> by its longest dotted prefix
            {ev.eol_date ? <>, end of life on {String(ev.eol_date)}</> : null}.
          </li>
        </ul>
      </Card>
    );
  }
  if (isBehind(f)) {
    // No advisory: endoflife.date's latest release of the line decided it.
    const b = behindFacts(f);
    return (
      <Card title="How this was decided">
        {head}
        <ul className="ref-list">
          <li>
            Source: <Link to="/intelligence">{b.source}</Link>
            {b.link && (
              <>
                {" "}
                (<ExtLink href={b.link}>release lines</ExtLink>)
              </>
            )}
          </li>
          <li>
            Release line <span className="mono">{b.cycle || "?"}</span> of {b.product}, matched from installed version{" "}
            <span className="mono">{b.installed}</span>.
          </li>
          <li>
            Latest release of the line: <span className="mono">{b.latest || "not recorded"}</span>
            {b.latestDate ? <>, released {b.latestDate}</> : null}.
          </li>
          {b.behind !== null && (
            <li>
              <span className="mono">{b.installed}</span> is {behindText(b.behind)}.
            </li>
          )}
        </ul>
        <p className="small">
          {b.product} point releases on a supported release line are its security and maintenance releases. Vulnerability (CVE) matching
          for {b.product} core is not available yet, so the missing releases are reported instead of the vulnerabilities they fix.
        </p>
      </Card>
    );
  }
  const ranges = rangesByAdvisory(ev.matched_ranges);
  const ids = matched.length > 0 ? matched.map((a) => a.id) : (f.sources ?? []);
  const feedOf = new Map(matched.map((a) => [a.id, a.feed]));
  const ecos = Array.isArray(ev.osv_ecosystems) ? ev.osv_ecosystems.map(String) : [];
  return (
    <Card title="How this was decided">
      {head}
      <p className="small">
        Installed <span className="mono">{String(ev.installed ?? f.version)}</span> of <span className="mono">{String(ev.osv_package ?? f.component_name)}</span>
        {ev.target_ecosystem ? (
          <>
            {" "}
            (ecosystem <span className="mono">{String(ev.target_ecosystem)}</span>)
          </>
        ) : null}
        , compared using <strong>{comparatorLabel(typeof ev.comparator === "string" ? ev.comparator : undefined)}</strong>
        {ev.feed ? (
          <>
            {" "}
            against the <Link to="/intelligence">{String(ev.feed)}</Link> feed
            {typeof ev.feed_last_success === "string" && (
              <>
                {" "}
                (synced <RelativeTime iso={ev.feed_last_success} /> at evaluation)
              </>
            )}
          </>
        ) : null}
        .
      </p>
      {ids.length === 0 ? (
        <p className="muted">No advisory source is recorded for this finding.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <caption className="sr-only">Advisories that produced this finding</caption>
            <thead>
              <tr>
                <th scope="col">Advisory</th>
                <th scope="col">Feed</th>
                <th scope="col">Ecosystem</th>
                <th scope="col">Affected range that matched</th>
              </tr>
            </thead>
            <tbody>
              {ids.map((id) => (
                <tr key={id}>
                  <td>
                    <ExtLink href={`https://osv.dev/vulnerability/${encodeURIComponent(id)}`}>
                      <span className="mono">{id}</span>
                    </ExtLink>
                  </td>
                  <td>{feedOf.get(id) ?? (ev.feed ? String(ev.feed) : <span className="muted">not recorded</span>)}</td>
                  <td className="mono small">{ecos.join(", ") || <span className="muted">not recorded</span>}</td>
                  <td className="mono small break">{(ranges.get(id) ?? []).join("; ") || <span className="muted">not recorded</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
