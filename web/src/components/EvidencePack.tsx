import { useMemo, useState, type ReactNode } from "react";
import { useAuth } from "../auth";
import { utcDay } from "../format";
import { allowedFrameworks, PACK_FRAMEWORKS, packURL, quarter, type PackFramework, type PackPeriod } from "../evidencePack";
import { ProNotice } from "./ProNotice";
import { Card } from "./ui";

type PeriodChoice = "last" | "this" | "custom";

/** The audit evidence pack on the Reports page: choose a period and frameworks, then download it. Nothing is built until a download. */
export function EvidencePackPanel({ projectID, from, to }: { projectID: number; from: string; to: string }) {
  const { has } = useAuth();
  const addon = has("compliance_addon");
  const [choice, setChoice] = useState<PeriodChoice>("last");
  const [selected, setSelected] = useState<PackFramework[]>(() => allowedFrameworks(addon));
  const period = useMemo(() => periodFor(choice, new Date(), from, to), [choice, from, to]);
  const frameworks = selected.filter((f) => allowedFrameworks(addon).includes(f));
  const toggle = (f: PackFramework) => setSelected((s) => (s.includes(f) ? s.filter((x) => x !== f) : [...s, f]));
  return (
    <EvidencePackView
      addon={addon}
      choice={choice}
      onChoice={setChoice}
      period={period}
      selected={frameworks}
      onToggle={toggle}
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
  projectID,
  addonNotice,
}: {
  addon: boolean;
  choice: PeriodChoice;
  onChoice: (c: PeriodChoice) => void;
  period: PackPeriod;
  selected: PackFramework[];
  onToggle: (f: PackFramework) => void;
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
                {f.name}{" "}
                <span className="muted">
                  (
                  {f.controls.map((c, i) => (
                    <span key={c} data-control={c}>
                      {i > 0 && ", "}
                      {c}
                    </span>
                  ))}
                  )
                </span>
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
        <p className="hint">
          The pack is built when you download it, from the same records as the report below; up to 10 packs an hour per organisation.
        </p>
      </div>
    </Card>
  );
}
