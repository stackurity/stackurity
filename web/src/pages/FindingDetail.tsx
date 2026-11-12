import { useEffect, useState, type ReactNode } from "react";
import { Link, useLocation, useParams } from "react-router";
import { api, safeHttpUrl, type Advisory, type Finding, type FindingDetail, type FindingEvidence } from "../api";
import { useLoad } from "../hooks";
import { absTime } from "../format";
import { Badge, Chip, KevBadge, PriorityBadge, SeverityBadge, VERIFICATION_EXPLAINED } from "../components/Badge";
import { EvidencePills, kindLabel, VexBadge, vexSummary } from "../components/Findings";
import { FindingSummary } from "../components/FindingSummary";
import { FindingHistory, PriorityWhy, WorkflowAlerts, WorkflowBadges, WorkflowDetails } from "../components/FindingWorkflow";
import { EvidenceStateBadge, Provenance } from "../components/Provenance";
import { isBehind } from "../behind";
import { RecommendedVersion, UpgradeDetails } from "../components/Upgrade";
import { WhyMatched } from "../components/Why";
import { DisclosureCard, ErrorBox, KeyValues, Loading, Notice, PageHeader, RelativeTime } from "../components/ui";
import { closedReason, countsAsRemediation } from "../resolution";
import { AskAI } from "../components/AskAI";
import { askFromFinding } from "../askAI";
import { sectionForHash, type SectionId } from "../findingLayers";
import { GroupCrumb } from "../components/nav";
import { advisoryCves, nvdUrl, osvUrl } from "../advisoryLinks";

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
  const cves = advisoryCves(a);
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
          <ExtLink href={osvUrl(a.id)}>osv.dev</ExtLink>
          {cves.map((c) => (
            <span key={c}>
              {" · "}
              <ExtLink href={nvdUrl(c)}>NVD {c}</ExtLink>
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

/**
 * The finding page in three layers. At the top, what to do now: what is
 * wrong, where, how urgent, the fix and who owns it. Then sections that
 * open on demand (why it matched, the upgrade, the priority, the workflow,
 * the affected component) and, collapsed, the technical details (how it was
 * decided, raw evidence, advisories, history). A link to a section's id
 * (/findings/12#history) opens it and scrolls to it.
 */
export function FindingDetailPage() {
  const { id } = useParams();
  const { hash } = useLocation();
  const res = useLoad(() => api.get<FindingDetail>(`/findings/${Number(id)}`), [id]);
  const [tick, setTick] = useState(0);
  const target = sectionForHash(hash);
  const loaded = !!res.data;

  // The section opens on render (forceOpen); then bring it, or the element
  // the link names inside it, into view.
  useEffect(() => {
    if (!loaded || !target) return;
    const t = setTimeout(() => {
      let raw = hash.replace(/^#/, "");
      try {
        raw = decodeURIComponent(raw);
      } catch {
        // keep it as typed
      }
      const el = document.getElementById(raw) ?? document.getElementById(target);
      // An id inside a closed <details> (a related advisory) opens it too.
      for (let d = el?.closest("details"); d; d = d.parentElement?.closest("details")) d.open = true;
      el?.scrollIntoView({ block: "start" });
    }, 50);
    return () => clearTimeout(t);
  }, [loaded, target, hash]);

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
  const why = res.data.why;
  const upgrade = f.status === "open" ? res.data.upgrade : null;
  const advisories = res.data.advisories ?? [];
  const ev = f.evidence ?? {};
  const sourceIds = new Set(f.sources ?? []);
  // The server splits matched sources from related advisories; the filter
  // keeps older servers (which returned one list) working.
  const matched = advisories.filter((a) => sourceIds.has(a.id));
  const related = [...advisories.filter((a) => !sourceIds.has(a.id)), ...(res.data.related_advisories ?? [])];
  const cve = f.kind === "vulnerability" ? (f.key.match(CVE_IN)?.[0] ?? null) : null;
  const showSources = f.kind === "vulnerability" && !isBehind(f);
  const opens = (s: SectionId) => target === s;
  const changed = () => {
    res.reload();
    setTick((t) => t + 1);
  };
  const verificationNotice = !why && VERIFICATION_EXPLAINED[f.verification] && (
    <Notice kind={f.verification === "confirmed" ? "info" : "warn"}>
      <strong>Verification: {f.verification.replace(/_/g, " ")}.</strong>{" "}
      {f.kind === "end_of_life" && f.verification === "confirmed"
        ? "The installed version was read from an authoritative source and belongs to a release line that is past its end-of-life date."
        : VERIFICATION_EXPLAINED[f.verification]}
      {f.verification === "needs_validation" && ev.advisory_level ? ` Sources rate it ${String(ev.advisory_level)}.` : ""}
    </Notice>
  );
  const feedStale = ev.feed_stale === true && (
    <Notice kind="warn">
      The <Link to="/intelligence">{String(ev.feed ?? "")}</Link> feed was stale when this was evaluated; newer advisory data may change
      the result.
    </Notice>
  );
  // Needs-validation, rejected and stale evidence is shown at the top: it
  // changes whether to act at all.
  const doubtful = f.verification !== "confirmed" || !!why?.needs_review;

  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <GroupCrumb />
        <Link to="/fixes">Fixes</Link> <span aria-hidden="true">/</span> <Link to="/fixes/issues">All issues</Link> <span aria-hidden="true">/</span> <span>{f.key}</span>
      </nav>
      <PageHeader help="findings"
        title={<span className="break">{f.title || f.key}</span>}
        sub={
          <span className="badges">
            <span className="mono">{f.key}</span>
            {cve && (
              <ExtLink href={nvdUrl(cve)}>NVD</ExtLink>
            )}
            <span>· {kindLabel(f.kind)}</span>
            <SeverityBadge severity={f.severity} score={f.score} />
            {f.known_exploited && <KevBadge />}
            <EvidenceStateBadge f={f} />
            <EvidencePills f={f} />
            <VexBadge f={f} />
            <Badge status={f.status} />
          </span>
        }
      />
      {f.status !== "open" && <ClosedNotice f={f} />}
      {f.known_exploited && (
        <div className="alert alert-error" role="alert">
          <strong>Known exploited:</strong> this vulnerability is in the CISA Known Exploited Vulnerabilities catalog: attackers are
          using it somewhere. That does not show it was exploited on this asset; prioritise it.
        </div>
      )}
      <WorkflowAlerts f={f} />
      {doubtful && verificationNotice}
      {f.vex && (
        <Notice kind={f.vex.status === "affected" ? "warn" : "info"}>
          <strong>{vexSummary(f.vex)}</strong>{" "}
          {f.vex.status === "not_affected" && !f.vex.applied && f.vex.request_status === "pending" && (
            <>
              A security or admin user decides it under <Link to="/approvals">Approvals</Link>; until then the issue stays open.
            </>
          )}
          {f.vex.status === "affected" && "The vendor says this component version is affected: plan the upgrade."}
          {f.vex.status === "under_investigation" && "The vendor has not decided yet."}{" "}
          <Link to={`/settings/vex/${f.vex.document_id}`}>The VEX document</Link>
        </Notice>
      )}

      <FindingSummary f={f} hasUpgrade={!!upgrade} onChanged={changed} />
      {f.status === "open" && <AskAI question={askFromFinding(f)} />}

      {(why || verificationNotice || feedStale) && (
        <DisclosureCard
          id="why"
          title="Why it matched"
          description="Why Stackurity believes this version is affected, how sure it is and what is missing."
          defaultOpen
          forceOpen={opens("why")}
        >
          {!doubtful && verificationNotice}
          {feedStale}
          {why && <WhyMatched why={why} bare />}
        </DisclosureCard>
      )}

      {upgrade && (
        <DisclosureCard
          id="upgrade"
          title="Upgrade recommendation"
          description="The version to move this installed copy to so every open issue on the package is fixed, and why."
          badges={<RecommendedVersion rec={upgrade} />}
          defaultOpen={upgrade.requires_major || !!upgrade.deprecated}
          forceOpen={opens("upgrade")}
        >
          <p className="hint">
            Built only from stored advisory, registry release and end-of-life data. Where data is missing it says so rather than guessing.
          </p>
          <UpgradeDetails rec={upgrade} issueFix={f.fixed_version} />
        </DisclosureCard>
      )}

      <DisclosureCard
        id="priority"
        title="Why this priority"
        description="Each factor that set the priority, its points and the risk policy behind it."
        badges={<PriorityBadge priority={f.priority} score={f.priority_score} />}
        forceOpen={opens("priority")}
      >
        <PriorityWhy f={f} epss={why?.epss} />
      </DisclosureCard>

      <DisclosureCard
        id="workflow"
        title="Workflow"
        description="Deadlines, who decided a snooze or acceptance and why, the incident and remediation runs."
        badges={<WorkflowBadges f={f} />}
        forceOpen={opens("workflow")}
      >
        <WorkflowDetails f={f} />
      </DisclosureCard>

      <DisclosureCard
        id="affected"
        title="Affected"
        description="Where this issue was found, the version installed there and the version that fixes it."
        forceOpen={opens("affected")}
      >
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
      </DisclosureCard>

      <h2 className="section-title">Technical details</h2>
      <p className="hint">The matching logic, raw evidence, advisory records and full history, for checking the result or an audit.</p>

      <DisclosureCard
        id="decided"
        title="How this was decided"
        description="Which source, ecosystem, version rules and range produced the result."
        forceOpen={opens("decided")}
      >
        <Provenance f={f} matched={matched} bare />
      </DisclosureCard>

      <DisclosureCard
        id="evidence"
        title="Evidence"
        description="Every fact recorded when this was evaluated, as stored."
        forceOpen={opens("evidence")}
      >
        <KeyValues entries={evidenceEntries(ev)} />
      </DisclosureCard>

      {showSources && (
        <DisclosureCard
          id="sources"
          title={`Sources (${matched.length})`}
          description="Advisories that matched this package and version, each with its own claim. Severities can differ between sources; the finding uses the highest."
          forceOpen={opens("sources")}
        >
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
        </DisclosureCard>
      )}

      <DisclosureCard
        id="history"
        title="History"
        description="Every action and automatic change on this finding, newest first."
        forceOpen={opens("history")}
      >
        <FindingHistory id={f.id} tick={tick} bare />
      </DisclosureCard>
    </>
  );
}
