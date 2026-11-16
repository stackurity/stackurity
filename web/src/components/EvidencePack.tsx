import { useMemo, useState, type ReactNode } from "react";
import { api, type ApiError, type EvidencePack } from "../api";
import { useAuth } from "../auth";
import { useLoad } from "../hooks";
import { utcDay } from "../format";
import { allowedFrameworks, PACK_FRAMEWORKS, packURL, quarter, type PackFramework, type PackPeriod } from "../evidencePack";
import { ProNotice } from "./ProNotice";
import { Card, ErrorBox, Loading } from "./ui";

type PeriodChoice = "last" | "this" | "custom";

/** The audit evidence pack on the Reports page: choose a period and frameworks, see what it holds, download it. */
export function EvidencePackPanel({ projectID, from, to }: { projectID: number; from: string; to: string }) {
  const { has } = useAuth();
  const addon = has("compliance_addon");
  const [choice, setChoice] = useState<PeriodChoice>("last");
  const [selected, setSelected] = useState<PackFramework[]>(() => allowedFrameworks(addon));
  const period = useMemo(() => periodFor(choice, new Date(), from, to), [choice, from, to]);
  const frameworks = selected.filter((f) => allowedFrameworks(addon).includes(f));
  const res = useLoad(
    () =>
      api.get<EvidencePack>("/reports/evidence-pack", {
        from: period.from,
        to: period.to,
        label: period.label,
        frameworks: frameworks.join(","),
      }),
    [period.from, period.to, frameworks.join(",")],
  );
  const toggle = (f: PackFramework) => setSelected((s) => (s.includes(f) ? s.filter((x) => x !== f) : [...s, f]));
  return (
    <EvidencePackView
      addon={addon}
      choice={choice}
      onChoice={setChoice}
      period={period}
      selected={frameworks}
      onToggle={toggle}
      pack={res.data}
      loading={res.loading}
      error={res.error}
      projectID={projectID}
      addonNotice={<ProNotice feature="compliance_addon" />}
    />
  );
}

/** The period for a choice: last full quarter, this quarter to date, or the report's own dates. */
export function periodFor(choice: PeriodChoice, today: Date, from: string, to: string): PackPeriod {
  if (choice === "last") return quarter(today, -1);
  if (choice === "this") {
    const q = quarter(today);
    const d = today.toISOString().slice(0, 10);
    return { from: q.from, to: d < q.to ? d : q.to, label: `${q.label} to date` };
  }
  return { from, to, label: "custom" };
}

export function EvidencePackView({
  addon,
  choice,
  onChoice,
  period,
  selected,
  onToggle,
  pack,
  loading,
  error,
  projectID,
  addonNotice,
}: {
  addon: boolean;
  choice: PeriodChoice;
  onChoice: (c: PeriodChoice) => void;
  period: PackPeriod;
  selected: PackFramework[];
  onToggle: (f: PackFramework) => void;
  pack?: EvidencePack;
  loading: boolean;
  error: ApiError | null;
  projectID: number;
  /** Shown without the add-on: how to get it. */
  addonNotice?: ReactNode;
}) {
  const none = selected.length === 0;
  return (
    <Card
      id="evidence-pack"
      title="Audit evidence pack"
      description={
        <>
          One download for your auditor: what Stackurity monitors and how often it checked, what it found, how fast it was fixed against
          your deadlines, and every exception with who approved it, mapped to the controls below. It is evidence for these controls; it does
          not say you are compliant or certified. Your auditor decides that.
        </>
      }
    >
      <div className="evidence-pack">
        <fieldset className="field">
          <legend>Period</legend>
          {(
            [
              ["last", "Last quarter"],
              ["this", "This quarter to date"],
              ["custom", "The dates above"],
            ] as [PeriodChoice, string][]
          ).map(([c, text]) => (
            <label key={c} className="check">
              <input type="radio" name="pack-period" checked={choice === c} onChange={() => onChoice(c)} /> {text}
            </label>
          ))}
          <p className="hint">
            {utcDay(period.from)} to {utcDay(period.to)} ({period.label}), UTC days.
          </p>
        </fieldset>
        <fieldset className="field">
          <legend>Frameworks</legend>
          {PACK_FRAMEWORKS.map((f) => {
            const locked = f.tier === "addon" && !addon;
            return (
              <label key={f.id} className={`check${locked ? " locked" : ""}`}>
                <input
                  type="checkbox"
                  checked={!locked && selected.includes(f.id)}
                  disabled={locked}
                  onChange={() => onToggle(f.id)}
                  aria-describedby={locked ? "pack-addon" : undefined}
                />{" "}
                {f.name} <span className="muted">({f.controls.join(", ")})</span>
                {locked && <span className="pro-badge">Compliance add-on</span>}
              </label>
            );
          })}
        </fieldset>
        {!addon && (
          <div id="pack-addon">
            {addonNotice}
          </div>
        )}
        <div className="actions">
          {(["pdf", "zip", "json"] as const).map((fmt) => (
            <a
              key={fmt}
              className={`btn${fmt === "pdf" ? " btn-primary" : ""}${none ? " disabled" : ""}`}
              href={none ? undefined : packURL(fmt, period, selected, projectID)}
              aria-disabled={none}
              download
            >
              Download {fmt.toUpperCase()}
            </a>
          ))}
        </div>
        <p className="hint">
          PDF: the report for the auditor. ZIP: the PDF, CSV tables of every row, {addon ? "an SBOM of each asset, the VEX statements, " : ""}
          and a manifest with each file&apos;s SHA-256. JSON: the same data for other tools.
          {none && " Choose at least one framework."}
        </p>
        <ErrorBox error={error} title="Could not build the evidence pack" />
        {loading && !pack && <Loading />}
        {pack && <PackSummary pack={pack} />}
      </div>
    </Card>
  );
}

function PackSummary({ pack }: { pack: EvidencePack }) {
  const m = pack.monitoring;
  const t = pack.time_to_fix;
  const share = (a: number, b: number) => (b > 0 ? `${((100 * a) / b).toFixed(1)}%` : "—");
  return (
    <>
      <ul className="pack-figures">
        <li>
          <strong>{m.assets_total}</strong> monitored assets, checked in <strong>{share(m.checks_completed, m.checks_expected)}</strong> of the
          hours monitored
        </li>
        <li>
          <strong>{pack.findings.closed}</strong> issues fixed, <strong>{share(t.within_sla, t.with_deadline)}</strong> by their deadline
        </li>
        <li>
          <strong>{pack.findings.open_at_end}</strong> open at the end ({pack.findings.open_overdue} overdue),{" "}
          <strong>{pack.exceptions.length}</strong> exceptions
        </li>
      </ul>
      {pack.frameworks.map((f) => (
        <section key={f.id} className="pack-framework">
          <h3>{f.name}</h3>
          <dl>
            {f.controls.map((c) => (
              <div key={c.id} data-control={c.id}>
                <dt>
                  {c.id} · {c.title}
                </dt>
                <dd>
                  {c.evidence}
                  {c.limit && <span className="muted"> Not shown by Stackurity: {c.limit}</span>}
                </dd>
              </div>
            ))}
          </dl>
        </section>
      ))}
    </>
  );
}
