import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router";
import { ApiError, siteChecks, type SiteCheck, type SiteCheckFinding, type SiteCheckGrade, type SiteCheckReport, type SiteCheckSoftware } from "../api";
import { useAuth } from "../auth";
import { useLoad } from "../hooks";
import { absTime, plural, relTime } from "../format";
import { Badge, SeverityBadge } from "../components/Badge";
import { Table, type Column } from "../components/Table";
import { Card, EmptyState, ErrorBox, GoodToKnow, Loading, PageHeader } from "../components/ui";
import { advisoryURL, gradeMeaning, gradeTone, kindLabel, softwareSummary } from "../websiteCheck";

/**
 * Reports > Website check (docs/website-check.md): what a public website
 * shows from the outside, matched to vulnerabilities and end of life.
 */
export function WebsiteCheckPage() {
  const { canAct } = useAuth();
  const [params, setParams] = useSearchParams();
  const openId = Number(params.get("check")) || 0;
  const list = useLoad(() => siteChecks.list(), []);
  const open = useLoad(() => (openId ? siteChecks.get(openId) : Promise.resolve(undefined)), [openId]);
  const [url, setUrl] = useState("");
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState<ApiError | null>(null);

  const run = async (e: FormEvent) => {
    e.preventDefault();
    setRunning(true);
    setRunError(null);
    try {
      const res = await siteChecks.run(url.trim());
      setParams({ check: String(res.id) });
      list.reload();
    } catch (err) {
      setRunError(err instanceof ApiError ? err : new ApiError(0, "error", String(err)));
    } finally {
      setRunning(false);
    }
  };

  const columns: Column<SiteCheck>[] = [
    { key: "host", header: "Website", cell: (c) => <Link to={`?check=${c.id}`}>{c.host}</Link> },
    {
      key: "issues",
      header: "Issues",
      cell: (c) => (
        <>
          {c.issues} {c.known_exploited > 0 && <Badge status="kev" tone="crit" label={`${c.known_exploited} known exploited`} />}
        </>
      ),
    },
    { key: "eol", header: "End of life", cell: (c) => (c.end_of_life ? <Badge status="eol" tone="bad" label={String(c.end_of_life)} /> : "0") },
    { key: "who", header: "Run by", cell: (c) => (c.via_api ? `${c.created_by_name} (API)` : c.created_by_name) },
    { key: "when", header: "When", cell: (c) => <span title={absTime(c.created_at)}>{relTime(c.created_at)}</span> },
  ];

  return (
    <>
      <PageHeader
        title="Website check"
        sub="See what a public website shows anyone who visits it: its server software, the JavaScript libraries it loads and their versions, with known vulnerabilities and end of life, plus leaked keys, cookie and form settings, outdated TLS and missing email records."
        help="website-check"
      />
      {canAct("engineer") ? (
        <Card title="Check a website" description="One visit, like a browser: the page and the scripts it loads, one TLS handshake and the domain's email records. Nothing is scanned or probed.">
          <form className="inline-form" onSubmit={run}>
            <label className="sr-only" htmlFor="site-url">
              Website address
            </label>
            <input id="site-url" type="text" placeholder="example.com" value={url} onChange={(e) => setUrl(e.target.value)} required disabled={running} />
            <button className="btn btn-primary" type="submit" disabled={running || !url.trim()}>
              {running ? "Checking…" : "Check"}
            </button>
          </form>
          <ErrorBox error={runError} title="The check did not run" />
        </Card>
      ) : (
        <GoodToKnow>Engineers and above can run website checks; you can open the ones run so far.</GoodToKnow>
      )}

      {openId > 0 && (
        <>
          <ErrorBox error={open.error} />
          {open.loading && !open.data && <Loading />}
          {open.data && <ReportView report={open.data.report} />}
        </>
      )}

      <Card title="Earlier checks" description="Checks run by your organisation, newest first.">
        <ErrorBox error={list.error} />
        {list.loading && !list.data ? (
          <Loading />
        ) : list.data && list.data.items.length > 0 ? (
          <Table rows={list.data.items} columns={columns} rowKey={(c) => c.id} />
        ) : (
          <EmptyState title="No website checks yet" why="Enter a domain above to see what it shows from the outside." />
        )}
      </Card>
    </>
  );
}

function ReportView({ report }: { report: SiteCheckReport }) {
  const s = report.summary;
  return (
    <>
      {report.grade && <GradeCard grade={report.grade} />}
      <Card
        title={report.host}
        description={`Checked ${absTime(report.checked_at)}${report.final_url !== report.url ? `, ended on ${report.final_url}` : ""}.`}
      >
        <ul className="count-list">
          <li>
            <span className="muted">Software found</span> <strong>{s.software}</strong>
          </li>
          <li>
            <span className="muted">Vulnerabilities</span> <strong>{s.issues}</strong>
          </li>
          <li>
            <span className="muted">Known exploited</span> <strong>{s.known_exploited}</strong>
          </li>
          <li>
            <span className="muted">End of life</span> <strong>{s.end_of_life}</strong>
          </li>
          <li>
            <span className="muted">Protection headers missing</span> <strong>{s.headers_missing}</strong>
          </li>
          {s.findings !== undefined && (
            <li>
              <span className="muted">Other problems</span> <strong>{s.findings}</strong>
            </li>
          )}
        </ul>
        {report.tls ? (
          <p className="small">
            TLS {report.tls.version}
            {report.tls.outdated && <Badge status="tls" tone="bad" label="outdated" />}, certificate from {report.tls.issuer || "unknown issuer"},{" "}
            {report.tls.days_left >= 0 ? `${plural(report.tls.days_left, "day")} left` : "expired"}.
          </p>
        ) : (
          <p className="small">Served over plain http, without encryption.</p>
        )}
        {report.notes.length > 0 && (
          <GoodToKnow>
            <ul>
              {report.notes.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          </GoodToKnow>
        )}
      </Card>

      {report.findings && <FindingsCard findings={report.findings} />}

      {report.software.length === 0 ? (
        <Card title="Software">
          <p className="muted">The site does not name its server software, and its page loads no library Stackurity recognises.</p>
        </Card>
      ) : (
        report.software.map((sw) => <SoftwareCard key={`${sw.name}@${sw.version}@${sw.where}`} sw={sw} />)
      )}

      <Card title="Browser protection headers" description="Headers that tell browsers to block common attacks on the site's visitors.">
        <ul className="plain-list">
          {report.headers.map((h) => (
            <li key={h.name}>
              <Badge status={h.present ? "present" : "missing"} tone={h.present ? "good" : "warn"} label={h.present ? "Sent" : "Missing"} /> <strong>{h.name}</strong>
              {h.advice && <span className="muted">: {h.advice}</span>}
            </li>
          ))}
        </ul>
      </Card>
    </>
  );
}

function GradeCard({ grade }: { grade: SiteCheckGrade }) {
  return (
    <Card
      title="Grade"
      description="Starts at 100 and loses points for each problem a visitor can see: critical 30, high 15, medium 6, low 2, at most 8 for missing headers. A critical problem or a vulnerability exploited in the wild keeps the grade at D or below, a high one at C or below."
    >
      <div className="site-grade">
        <div className="site-grade-letter" data-tone={gradeTone(grade.letter)} role="img" aria-label={`Grade ${grade.letter}`}>
          {grade.letter}
        </div>
        <div className="site-grade-body">
          <p>{gradeMeaning(grade)}</p>
          {grade.deductions.length > 0 && (
            <ul>
              {grade.deductions.map((d, i) => (
                <li key={i}>
                  <span className="site-grade-points">−{d.points}</span> <SeverityBadge severity={d.severity} /> {d.what}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </Card>
  );
}

function FindingsCard({ findings }: { findings: SiteCheckFinding[] }) {
  return (
    <Card
      title="Other problems"
      description="What the page's code, cookies and forms show, whether the server still accepts TLS 1.0 or 1.1, and the domain's SPF and DMARC email records."
    >
      {findings.length === 0 ? (
        <p className="muted">None found: no keys in the page's code, cookies and forms are set safely, and the email records are in place.</p>
      ) : (
        <ul className="plain-list">
          {findings.map((f) => (
            <li key={f.id}>
              <SeverityBadge severity={f.severity} /> <strong>{f.title}</strong> <span className="muted small">{f.category}</span>
              <div className="small">{f.detail}</div>
              <div className="small">
                <strong>Fix:</strong> {f.fix}
              </div>
              {f.where && f.where.length > 0 && (
                <ul className="small muted">
                  {f.where.map((w) => (
                    <li key={w}>{w}</li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function SoftwareCard({ sw }: { sw: SiteCheckSoftware }) {
  return (
    <Card title={`${sw.name} ${sw.version}`} description={`${kindLabel(sw.kind)}, seen in ${sw.where.startsWith("http") ? "a script it loads" : `the ${sw.where}`}. ${softwareSummary(sw)}`}>
      {sw.end_of_life && (
        <p>
          {sw.end_of_life.ended ? <Badge status="eol" tone="bad" label="End of life" /> : <Badge status="supported" tone="good" label="Supported" />} {sw.end_of_life.product}{" "}
          {sw.end_of_life.cycle}
          {sw.end_of_life.eol_date && `: support ${sw.end_of_life.ended ? "ended" : "ends"} ${sw.end_of_life.eol_date.slice(0, 10)}`}
          {sw.end_of_life.latest && `. Latest in this line: ${sw.end_of_life.latest}`}
        </p>
      )}
      {sw.coverage && <p className="muted small">{sw.coverage}</p>}
      {sw.issues.length > 0 && (
        <Table
          rows={sw.issues}
          rowKey={(i) => i.id}
          columns={[
            {
              key: "id",
              header: "Issue",
              cell: (i) => (
                <>
                  <a href={advisoryURL(i.id)} target="_blank" rel="noreferrer">
                    {i.id}
                  </a>{" "}
                  {i.known_exploited && <Badge status="kev" tone="crit" label="Known exploited" />}
                  {i.summary && <div className="muted small">{i.summary}</div>}
                </>
              ),
            },
            { key: "sev", header: "Severity", cell: (i) => <SeverityBadge severity={i.severity} score={i.score ?? null} /> },
            { key: "fix", header: "Fixed in", cell: (i) => i.fixed_in || <span className="muted">no fix yet</span> },
          ]}
        />
      )}
    </Card>
  );
}
