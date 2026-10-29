import { useState, type ReactNode } from "react";
import { Link, useParams } from "react-router";
import { api, safeHttpUrl, type Advisory, type Finding, type FindingDetail, type FindingEvidence } from "../api";
import { useLoad } from "../hooks";
import { absTime } from "../format";
import { Badge, Chip, KevBadge, SeverityBadge, VERIFICATION_EXPLAINED } from "../components/Badge";
import { EvidencePills, kindLabel } from "../components/Findings";
import { FindingFixGroup } from "../components/FixGroups";
import { FindingHistory, WorkflowPanel } from "../components/FindingWorkflow";
import { EvidenceStateBadge, Provenance } from "../components/Provenance";
import { UpgradeCard } from "../components/Upgrade";
import { WhyMatched } from "../components/Why";
import { Card, ErrorBox, KeyValues, Loading, Notice, PageHeader, RelativeTime } from "../components/ui";
import { closedReason, countsAsRemediation } from "../resolution";

const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;
const CVE_IN = /CVE-\d{4}-\d{4,}/i;

function ExtLink({ href, children }: { href: string | null; children: ReactNode }) {
  const safe = safeHttpUrl(href);
  if (!safe) return <>{children}</>;
  return (
    <a href={safe} target="_blank" rel="noopener noreferrer">
      {children}
      <span className="sr-only"> (opens in a new tab)</span>
    </a>
  );
}

/** Why the finding closed: remediation, or a closure with nothing fixed on the asset, which reports do not count. */
function ClosedNotice({ f }: { f: Finding }) {
  const kind = f.resolution_kind ?? "";
  const reason = closedReason(kind, f.resolution, f.resolution_detail);
  const successor = f.resolution_detail?.successor;
  if (countsAsRemediation(kind) || kind === "") {
    return (
      <Notice kind="success">
        Resolved <RelativeTime iso={f.resolved_at} />: {reason}.
      </Notice>
    );
  }
  return (
    <Notice kind="info">
      <strong>Closed: {reason}.</strong> Closed <RelativeTime iso={f.resolved_at} />. Nothing was fixed on this asset, so this is not counted as
      remediation in the outcomes or evidence reports.
      {successor ? (
        <>
          {" "}
          The issue continues as <Link to={`/findings/${successor}`}>finding #{successor}</Link>.
        </>
      ) : null}
    </Notice>
  );
}

function RecommendedAction({ f, hasUpgrade }: { f: Finding; hasUpgrade: boolean }) {
  const ev = f.evidence ?? {};
  if (f.kind === "end_of_life") {
    return (
      <div className="action-box">
        <p>
          <strong>Recommended action:</strong> move {f.component_name} off the {String(ev.cycle ?? "current")} release line to a
          supported release{ev.latest_in_cycle ? ` (the last release of this line was ${String(ev.latest_in_cycle)})` : ""}.
          {ev.link && (
            <>
              {" "}
              <ExtLink href={String(ev.link)}>Support dates on endoflife.date</ExtLink>.
            </>
          )}
        </p>
      </div>
    );
  }
  if (!f.fixed_version) {
    return (
      <div className="action-box action-none">
        <p>
          <strong>No fixed version listed by any source.</strong> Check the advisories below for workarounds, or consider replacing{" "}
          {f.component_name}.
        </p>
      </div>
    );
  }
  return (
    <div className="action-box">
      <p>
        <strong>Fixes this issue:</strong> upgrade <span className="mono">{f.component_name}</span> from{" "}
        <span className="mono">{f.version}</span> to <span className="mono">{f.fixed_version}</span> or later
        {f.direct === false ? " (it is a transitive dependency: upgrade the package that pulls it in, or add an override)" : ""}.
        {hasUpgrade ? " The upgrade recommendation below covers every open finding on this package." : ""}
      </p>
    </div>
  );
}

function evidenceEntries(ev: FindingEvidence): [string, ReactNode][] {
  const out: [string, ReactNode][] = [];
  const keys = Object.keys(ev).sort();
  for (const k of keys) {
    const v = ev[k];
    if (v === null || v === undefined || v === "") continue;
    let node: ReactNode;
    if (Array.isArray(v)) {
      node =
        v.length === 0 ? (
          <span className="muted">none</span>
        ) : (
          <ul className="ref-list mono small">
            {v.map((x, i) => (
              <li key={i}>{String(x)}</li>
            ))}
          </ul>
        );
    } else if (typeof v === "boolean") {
      node = v ? "yes" : "no";
    } else if (k === "link") {
      node = <ExtLink href={String(v)}>{String(v)}</ExtLink>;
    } else if (k === "feed_last_success") {
      node = <RelativeTime iso={String(v)} />;
    } else if (typeof v === "object") {
      node = <span className="mono small break">{JSON.stringify(v)}</span>;
    } else {
      node = <span className="mono break">{String(v)}</span>;
    }
    out.push([k.replace(/_/g, " "), node]);
  }
  return out;
}

function AdvisoryCard({ a, matched }: { a: Advisory; matched: boolean }) {
  const refs = (a.references ?? []).filter((r) => safeHttpUrl(r.url));
  const aliases = a.aliases ?? [];
  const cves = [a.id, ...aliases].filter((x) => CVE_RE.test(x));
  return (
    <section className={`card advisory${a.withdrawn ? " withdrawn" : ""}`} aria-labelledby={`adv-${a.id}`}>
      <header className="card-head">
        <h3 id={`adv-${a.id}`} className="badges">
          <span className="mono">{a.id}</span>
          <SeverityBadge severity={a.severity} score={a.score} />
          {a.known_exploited && <KevBadge />}
          {a.withdrawn && <Badge status="withdrawn" tone="muted" label={`withdrawn ${absTime(a.withdrawn)}`} />}
          {!matched && <Badge status="related" tone="muted" label="did not match this package" />}
        </h3>
        <div className="card-actions small">
          <ExtLink href={`https://osv.dev/vulnerability/${encodeURIComponent(a.id)}`}>osv.dev</ExtLink>
          {cves.map((c) => (
            <span key={c}>
              {" · "}
              <ExtLink href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c)}`}>NVD {c}</ExtLink>
            </span>
          ))}
        </div>
      </header>
      {a.summary && <p>{a.summary}</p>}
      <KeyValues
        entries={[
          ["feed", a.feed],
          ["severity source", a.severity_source || <span className="muted">not stated</span>],
          ...(a.vector ? ([["vector", <span className="mono small break">{a.vector}</span>]] as [string, ReactNode][]) : []),
          [
            "aliases",
            aliases.length ? (
              <span className="chips">
                {aliases.map((x) => (
                  <Chip key={x}>
                    <span className="mono">{x}</span>
                  </Chip>
                ))}
              </span>
            ) : (
              <span className="muted">none</span>
            ),
          ],
          ["published", a.published ? absTime(a.published) : <span className="muted">unknown</span>],
          ["modified", absTime(a.modified)],
        ]}
      />
      {refs.length > 0 && (
        <details>
          <summary>References ({refs.length})</summary>
          <ul className="ref-list small">
            {refs.map((r, i) => (
              <li key={i}>
                {r.type && <span className="muted">{r.type.toLowerCase()}: </span>}
                <ExtLink href={r.url!}>{r.url}</ExtLink>
              </li>
            ))}
          </ul>
        </details>
      )}
    </section>
  );
}

export function FindingDetailPage() {
  const { id } = useParams();
  const res = useLoad(() => api.get<FindingDetail>(`/findings/${Number(id)}`), [id]);
  const [tick, setTick] = useState(0);

  if (res.error)
    return (
      <>
        <PageHeader help="findings" title="Finding" />
        <ErrorBox error={res.error} title="Could not load finding" />
        <p>
          <Link to="/fixes/issues">Back to all issues</Link>
        </p>
      </>
    );
  if (!res.data) return <Loading />;
  const f = res.data.finding;
  const advisories = res.data.advisories ?? [];
  const ev = f.evidence ?? {};
  const sourceIds = new Set(f.sources ?? []);
  // The server splits matched sources from related advisories; the filter
  // keeps older servers (which returned one list) working.
  const matched = advisories.filter((a) => sourceIds.has(a.id));
  const related = [...advisories.filter((a) => !sourceIds.has(a.id)), ...(res.data.related_advisories ?? [])];
  const cve = f.kind === "vulnerability" ? (f.key.match(CVE_IN)?.[0] ?? null) : null;

  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/fixes">Fixes</Link> <span aria-hidden="true">/</span> <Link to="/fixes/issues">All issues</Link> <span aria-hidden="true">/</span> <span>{f.key}</span>
      </nav>
      <PageHeader help="findings"
        title={<span className="break">{f.title || f.key}</span>}
        sub={
          <span className="badges">
            <span className="mono">{f.key}</span>
            {cve && (
              <ExtLink href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.toUpperCase())}`}>NVD</ExtLink>
            )}
            <span>· {kindLabel(f.kind)}</span>
            <SeverityBadge severity={f.severity} score={f.score} />
            {f.known_exploited && <KevBadge />}
            <EvidenceStateBadge f={f} />
            <EvidencePills f={f} />
            <Badge status={f.status} />
          </span>
        }
      />
      {res.data.why && <WhyMatched why={res.data.why} />}
      {f.status !== "open" && <ClosedNotice f={f} />}
      {f.known_exploited && (
        <div className="alert alert-error" role="alert">
          <strong>Known exploited:</strong> this vulnerability is in the CISA Known Exploited Vulnerabilities catalog: attackers are
          using it somewhere. That does not show it was exploited on this asset; prioritise it.
        </div>
      )}
      {!res.data.why && VERIFICATION_EXPLAINED[f.verification] && (
        <Notice kind={f.verification === "confirmed" ? "info" : "warn"}>
          <strong>Verification: {f.verification.replace(/_/g, " ")}.</strong>{" "}
          {f.kind === "end_of_life" && f.verification === "confirmed"
            ? "The installed version was read from an authoritative source and belongs to a release line that is past its end-of-life date."
            : VERIFICATION_EXPLAINED[f.verification]}
          {f.verification === "needs_validation" && ev.advisory_level ? ` Sources rate it ${String(ev.advisory_level)}.` : ""}
        </Notice>
      )}
      {ev.feed_stale === true && (
        <Notice kind="warn">
          The <Link to="/intelligence">{String(ev.feed ?? "")}</Link> feed was stale when this was evaluated; newer advisory data may
          change the result.
        </Notice>
      )}
      <FindingFixGroup f={f} />
      {f.status === "open" && <RecommendedAction f={f} hasUpgrade={!!res.data.upgrade} />}
      {f.status === "open" && res.data.upgrade && <UpgradeCard rec={res.data.upgrade} />}
      <WorkflowPanel
        f={f}
        epss={res.data.why?.epss}
        onChanged={() => {
          res.reload();
          setTick((t) => t + 1);
        }}
      />

      <Provenance f={f} matched={matched} />

      <div className="grid-2">
        <Card title="Affected">
          <KeyValues
            entries={[
              ["component", <Link to={`/components/${f.component_id}`}>{f.component_name}</Link>],
              ["type", f.component_type],
              ["installed version", <span className="mono">{f.version || "unknown"}</span>],
              ["fixed version", f.fixed_version ? <span className="mono">{f.fixed_version}</span> : <span className="muted">none listed</span>],
              ["dependency", f.direct === null ? <span className="muted">unknown</span> : f.direct ? "direct" : "transitive"],
              ["location", f.location ? <span className="mono small break">{f.location}</span> : <span className="muted">none</span>],
              ["asset", <Link to={`/assets/${f.asset_id}?tab=findings`}>{f.asset_name}</Link>],
              ["asset kind", f.asset_kind],
              ["environment", f.environment || <span className="muted">not set</span>],
              ["first seen", <RelativeTime iso={f.first_seen} />],
              ["last evaluated", <RelativeTime iso={f.last_seen} />],
              ["sources", (f.sources ?? []).join(", ") || <span className="muted">none</span>],
            ]}
          />
        </Card>
        <Card title="Evidence">
          <p className="hint">Why Stackurity believes this component is affected.</p>
          <KeyValues entries={evidenceEntries(ev)} />
        </Card>
      </div>

      {f.kind === "vulnerability" && (
        <>
          <h2 className="section-title">Sources ({matched.length})</h2>
          <p className="hint">
            Advisories that matched this package and version, each with its own claim. Severities can differ between sources; the
            finding uses the highest.
          </p>
          {matched.length === 0 ? (
            <p className="muted">No advisory records are stored for this finding's sources.</p>
          ) : (
            matched.map((a) => <AdvisoryCard key={`${a.feed}|${a.id}`} a={a} matched />)
          )}
          {related.length > 0 && (
            <details className="related">
              <summary>
                Related advisories for the same vulnerability ({related.length}), about other packages or ecosystems
              </summary>
              {related.map((a) => (
                <AdvisoryCard key={`${a.feed}|${a.id}`} a={a} matched={false} />
              ))}
            </details>
          )}
        </>
      )}
      <FindingHistory id={f.id} tick={tick} />
    </>
  );
}
