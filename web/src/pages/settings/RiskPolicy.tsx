import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router";
import {
  api,
  DEFAULT_EXCEPTION_MAX_DAYS,
  PRIORITIES,
  type RiskPolicy,
  type RiskPolicyPreview,
  type RiskPolicyResponse,
  type RiskPreviewFinding,
  type SOSRule,
} from "../../api";
import { useAuth } from "../../auth";
import { forgetRiskPolicy, useAction, useLoad } from "../../hooks";
import { PriorityBadge, SosBadge } from "../../components/Badge";
import { Table, type Column } from "../../components/Table";
import { Card, ErrorBox, Loading, Notice, PageHeader, RelativeTime } from "../../components/ui";
import { plural } from "../../format";

const SEVERITY_KEYS = ["critical", "high", "medium", "low", "none", "unknown"];
const CRITICALITY_KEYS = ["critical", "high", "medium", "low", "unknown"];

/** Number input that keeps the typed text (e.g. "-" or "0.") until it parses. */
function NumField({
  id,
  label,
  value,
  onChange,
  step = 0.1,
  min,
  max,
  hint,
}: {
  id: string;
  label: string;
  value: number;
  onChange: (n: number) => void;
  step?: number;
  min?: number;
  max?: number;
  hint?: string;
}) {
  const [text, setText] = useState(String(value));
  useEffect(() => {
    if (Number(text) !== value) setText(String(value));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        className="num-input"
        type="number"
        step={step}
        min={min}
        max={max}
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          const n = e.target.valueAsNumber;
          if (!Number.isNaN(n)) onChange(n);
        }}
      />
      {hint && <p className="hint">{hint}</p>}
    </div>
  );
}

type Tri = "any" | "yes" | "no";
const toTri = (b: boolean | undefined): Tri => (b === undefined ? "any" : b ? "yes" : "no");
const fromTri = (t: Tri): boolean | undefined => (t === "any" ? undefined : t === "yes");

function TriSelect({ id, label, value, onChange, hint }: { id: string; label: string; value: boolean | undefined; onChange: (b: boolean | undefined) => void; hint?: string }) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <select id={id} value={toTri(value)} onChange={(e) => onChange(fromTri(e.target.value as Tri))}>
        <option value="any">Any</option>
        <option value="yes">Yes</option>
        <option value="no">No</option>
      </select>
      {hint && <p className="hint">{hint}</p>}
    </div>
  );
}

function TagsField({ id, label, value, onChange }: { id: string; label: string; value: string[]; onChange: (v: string[]) => void }) {
  const [draft, setDraft] = useState("");
  const add = () => {
    const v = draft.trim();
    if (v && !value.includes(v)) onChange([...value, v]);
    setDraft("");
  };
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <div className="tag-input">
        {value.map((t) => (
          <span key={t} className="chip">
            {t}
            <button type="button" aria-label={`Remove ${t}`} onClick={() => onChange(value.filter((x) => x !== t))}>
              ×
            </button>
          </span>
        ))}
        <input
          id={id}
          value={draft}
          placeholder="add and press Enter"
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === ",") {
              e.preventDefault();
              add();
            }
          }}
          onBlur={add}
        />
      </div>
    </div>
  );
}

const pts = (n: number) => (Number.isInteger(n) ? String(n) : n.toFixed(2).replace(/0$/, ""));

/** What a proposed policy does to the workspace's open findings. */
function PreviewCard({ pv }: { pv: RiskPolicyPreview }) {
  const cols: Column<RiskPreviewFinding>[] = [
    {
      key: "finding",
      header: "Finding",
      cell: (f) => (
        <Link to={`/findings/${f.id}`} className="break">
          {f.title || f.key}
        </Link>
      ),
    },
    { key: "asset", header: "Asset", cell: (f) => <Link to={`/assets/${f.asset_id}?tab=findings`}>{f.asset_name}</Link> },
    {
      key: "change",
      header: "Priority",
      cell: (f) => (
        <span className="badges">
          <PriorityBadge priority={f.before} score={f.score_before} />
          {f.sos_before && <SosBadge />}
          <span aria-label="becomes">-&gt;</span>
          <PriorityBadge priority={f.after} score={f.score_after} />
          {f.sos_after && <SosBadge />}
        </span>
      ),
    },
    {
      key: "factors",
      header: "What changed",
      cell: (f) =>
        f.factors.length === 0 ? (
          <span className="muted small">thresholds or SOS rules only</span>
        ) : (
          <ul className="ref-list small">
            {f.factors.map((x) => (
              <li key={x.name}>
                {x.name}: {pts(x.before)} -&gt; {pts(x.after)}
              </li>
            ))}
          </ul>
        ),
    },
  ];
  const nothing = pv.priority_changed === 0 && pv.sos_changed === 0;
  return (
    <Card title="Impact of these changes">
      <p className="hint">
        Every open finding in this workspace ({pv.findings}) scored under the policy in force and under the proposed one, from the same
        evidence. Nothing has been saved.
        {pv.changed_fields.length > 0 && <> Changed: {pv.changed_fields.map((f) => f.replace(/_/g, " ")).join(", ")}.</>}
      </p>
      {nothing ? (
        <Notice kind="info">
          No finding changes priority or SOS.{" "}
          {pv.score_changed > 0 ? `${plural(pv.score_changed, "finding")} change score without crossing a threshold.` : ""}
          {pv.changed_fields.some((f) => f === "sla" || f === "exception_max_days") ? " Deadline and exception limits still change." : ""}
        </Notice>
      ) : (
        <Notice kind="warn">
          <strong>{plural(pv.priority_changed, "finding")} change priority</strong> ({pv.raised} raised, {pv.lowered} lowered)
          {pv.sos_changed > 0 && <>, {plural(pv.sos_changed, "finding")} gain or lose SOS</>}. Deadlines follow the new priority.
        </Notice>
      )}
      <div className="table-wrap">
        <table className="table">
          <caption className="sr-only">Open findings per priority before and after</caption>
          <thead>
            <tr>
              <th scope="col"></th>
              {PRIORITIES.map((p) => (
                <th key={p} scope="col" className="num">
                  {p}
                </th>
              ))}
              <th scope="col" className="num">
                SOS
              </th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <th scope="row">Now</th>
              {PRIORITIES.map((p) => (
                <td key={p} className="num">
                  {pv.before[p] ?? 0}
                </td>
              ))}
              <td className="num">{pv.sos_before}</td>
            </tr>
            <tr>
              <th scope="row">Proposed</th>
              {PRIORITIES.map((p) => {
                const d = (pv.after[p] ?? 0) - (pv.before[p] ?? 0);
                return (
                  <td key={p} className="num">
                    {pv.after[p] ?? 0}
                    {d !== 0 && <span className="muted small"> ({d > 0 ? `+${d}` : d})</span>}
                  </td>
                );
              })}
              <td className="num">{pv.sos_after}</td>
            </tr>
          </tbody>
        </table>
      </div>
      {pv.sample.length > 0 && (
        <>
          <h3 className="section-title">
            Findings that change
            {pv.priority_changed + pv.sos_changed > pv.sample.length ? ` (the ${pv.sample.length} largest moves)` : ""}
          </h3>
          <Table columns={cols} rows={pv.sample} rowKey={(f) => f.id} caption="Findings whose priority or SOS changes" />
        </>
      )}
      {pv.stored_differs > 0 && (
        <p className="hint">
          {plural(pv.stored_differs, "finding")} already differ from their stored priority because their evidence changed since the
          last scoring; they move on the next cycle whether or not you save.
        </p>
      )}
    </Card>
  );
}

function cleanRule(r: SOSRule): SOSRule {
  const out: SOSRule = { name: r.name.trim() };
  if (r.min_priority) out.min_priority = r.min_priority;
  if (r.min_severity) out.min_severity = r.min_severity;
  for (const k of ["known_exploited", "production", "internet_exposed", "fix_available"] as const) if (r[k] !== undefined) out[k] = r[k];
  return out;
}

export function RiskPolicyPage() {
  const { can } = useAuth();
  const admin = can("admin");
  const res = useLoad(() => api.get<RiskPolicyResponse>("/risk-policy"), []);
  const [p, setP] = useState<RiskPolicy | null>(null);
  const [saved, setSaved] = useState(false);
  const act = useAction();
  // The preview and the exact body it was computed for: Save needs a preview
  // of what is about to be saved.
  const [preview, setPreview] = useState<{ body: string; data: RiskPolicyPreview } | null>(null);
  const previewAct = useAction();

  useEffect(() => {
    if (res.data) setP(structuredClone(res.data.policy));
  }, [res.data]);

  if (res.error) return <ErrorBox error={res.error} title="Could not load risk policy" />;
  if (!res.data || !p) return <Loading />;

  const set = <K extends keyof RiskPolicy>(k: K, v: RiskPolicy[K]) => {
    setSaved(false);
    setP({ ...p, [k]: v });
  };
  const rules = p.sos_rules ?? [];
  const setRule = (i: number, r: SOSRule) => set("sos_rules", rules.map((x, j) => (j === i ? r : x)));
  const dirty = JSON.stringify(p) !== JSON.stringify(res.data.policy);

  const exceptionDays = p.exception_max_days ?? DEFAULT_EXCEPTION_MAX_DAYS;
  const exceptionDaysValid = Number.isInteger(exceptionDays) && exceptionDays >= 1 && exceptionDays <= 730;

  const bodyOf = (policy: RiskPolicy) => ({ ...policy, sos_rules: (policy.sos_rules ?? []).map(cleanRule) });
  const body = bodyOf(p);
  const previewed = preview !== null && preview.body === JSON.stringify(body);
  const runPreview = async () => {
    const b = bodyOf(p);
    const r = await previewAct.run(() => api.post<RiskPolicyPreview>("/risk-policy/preview", b));
    if (r) setPreview({ body: JSON.stringify(b), data: r });
  };
  const save = async () => {
    setSaved(false);
    const r = await act.run(() => api.put<{ policy: RiskPolicy }>("/risk-policy", body));
    if (r) {
      setSaved(true);
      setPreview(null);
      forgetRiskPolicy();
      res.reload();
    }
  };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!exceptionDaysValid || !previewed) return;
    void save();
  };
  const reset = () => {
    // The defaults go into the form; they are previewed and saved like any change.
    setSaved(false);
    setP(structuredClone(res.data!.default));
  };
  const last = res.data.last_change;

  return (
    <>
      <PageHeader help="risk-policy"
        title="Risk policy"
        sub={
          <>
            How findings are scored into priorities P1 to P4, their deadlines, and which ones are SOS. Version <code>{res.data.version}</code>.{" "}
            {last ? (
              <>
                Last changed by <strong>{last.actor_name || last.actor_type}</strong> <RelativeTime iso={last.at} /> (
                <Link to="/audit?object_type=settings">history</Link>).
              </>
            ) : (
              "Never changed: the built-in defaults apply."
            )}
          </>
        }
        actions={
          admin && (
            <button type="button" className="btn" onClick={reset} disabled={act.pending}>
              Load defaults
            </button>
          )
        }
      />
      {!admin && <Notice kind="info">Read-only: only administrators can change the risk policy.</Notice>}
      <form className="form" onSubmit={submit}>
        <fieldset disabled={!admin || act.pending} className="field">
          <legend className="sr-only">Risk policy</legend>
          <Card title="Base score">
            <p className="hint">
              A finding starts from its CVSS score when one is known, otherwise from the value for its severity. End-of-life findings use
              the end-of-life base.
            </p>
            <div className="form-grid">
              {SEVERITY_KEYS.map((k) => (
                <NumField
                  key={k}
                  id={`sev-${k}`}
                  label={`Severity ${k}`}
                  value={p.severity_base[k] ?? 0}
                  onChange={(n) => set("severity_base", { ...p.severity_base, [k]: n })}
                />
              ))}
              <NumField id="eol" label="End of life" value={p.eol_base} onChange={(n) => set("eol_base", n)} />
            </div>
          </Card>
          <Card title="Adjustments (points added)">
            <div className="form-grid">
              <NumField id="kev" label="Known exploited (CISA KEV)" value={p.known_exploited} onChange={(n) => set("known_exploited", n)} />
              <NumField id="exp" label="Internet exposed" value={p.internet_exposed} onChange={(n) => set("internet_exposed", n)} />
              <NumField id="expu" label="Exposure unknown" value={p.exposure_unknown} onChange={(n) => set("exposure_unknown", n)} />
              <NumField id="prod" label="Production environment" value={p.production} onChange={(n) => set("production", n)} />
              <NumField
                id="envu"
                label="Environment unknown"
                value={p.environment_unknown ?? 0}
                onChange={(n) => set("environment_unknown", n)}
                hint="Asset has no environment. At most the production value."
              />
              <NumField id="fix" label="Fix available" value={p.fix_available} onChange={(n) => set("fix_available", n)} />
              <NumField id="over" label="Overdue" value={p.overdue} onChange={(n) => set("overdue", n)} />
              <NumField id="dev" label="Dev-only dependency" value={p.dev_dependency} onChange={(n) => set("dev_dependency", n)} hint="Usually negative." />
              {CRITICALITY_KEYS.map((k) => (
                <NumField
                  key={k}
                  id={`crit-${k}`}
                  label={`Asset criticality ${k}`}
                  value={p.criticality[k] ?? 0}
                  onChange={(n) => set("criticality", { ...p.criticality, [k]: n })}
                />
              ))}
            </div>
          </Card>
          <Card title="Evidence multipliers">
            <div className="form-grid">
              <NumField
                id="mul-nv"
                label="Version not confirmed"
                value={p.needs_validation_multiplier}
                step={0.05}
                min={0.05}
                max={1}
                onChange={(n) => set("needs_validation_multiplier", n)}
                hint="Between 0 and 1."
              />
              <NumField id="mul-st" label="Stale asset" value={p.stale_multiplier} step={0.05} min={0.05} max={1} onChange={(n) => set("stale_multiplier", n)} hint="Between 0 and 1." />
            </div>
          </Card>
          <Card title="Production environments">
            <TagsField
              id="prod-envs"
              label="Environment names treated as production"
              value={p.production_environments ?? []}
              onChange={(v) => set("production_environments", v)}
            />
          </Card>
          <Card title="Priority thresholds and deadlines">
            <div className="form-grid">
              <NumField id="t1" label="P1 at score ≥" value={p.thresholds.p1} onChange={(n) => set("thresholds", { ...p.thresholds, p1: n })} />
              <NumField id="t2" label="P2 at score ≥" value={p.thresholds.p2} onChange={(n) => set("thresholds", { ...p.thresholds, p2: n })} />
              <NumField id="t3" label="P3 at score ≥" value={p.thresholds.p3} onChange={(n) => set("thresholds", { ...p.thresholds, p3: n })} hint="Below this is P4. Must be P1 > P2 > P3." />
            </div>
            <div className="table-wrap">
              <table className="table">
                <caption className="sr-only">Deadlines per priority</caption>
                <thead>
                  <tr>
                    <th scope="col">Priority</th>
                    <th scope="col">Acknowledge within (hours)</th>
                    <th scope="col">Fix within (days)</th>
                  </tr>
                </thead>
                <tbody>
                  {PRIORITIES.map((pr) => {
                    const s = p.sla[pr] ?? { ack_hours: 0, fix_days: 0 };
                    return (
                      <tr key={pr}>
                        <th scope="row">{pr}</th>
                        <td>
                          <label className="sr-only" htmlFor={`ack-${pr}`}>
                            {pr} acknowledge within hours
                          </label>
                          <input
                            id={`ack-${pr}`}
                            className="num-input"
                            type="number"
                            min={1}
                            step={1}
                            value={String(s.ack_hours)}
                            onChange={(e) => set("sla", { ...p.sla, [pr]: { ...s, ack_hours: Math.round(Number(e.target.value) || 0) } })}
                          />
                        </td>
                        <td>
                          <label className="sr-only" htmlFor={`fix-${pr}`}>
                            {pr} fix within days
                          </label>
                          <input
                            id={`fix-${pr}`}
                            className="num-input"
                            type="number"
                            min={1}
                            step={1}
                            value={String(s.fix_days)}
                            onChange={(e) => set("sla", { ...p.sla, [pr]: { ...s, fix_days: Math.round(Number(e.target.value) || 0) } })}
                          />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </Card>
          <Card title="Exceptions">
            <p className="hint">
              Suppressions and risk acceptances always expire; this is the longest expiry anyone can set. The finding returns as new
              when it passes.
            </p>
            <div className="form-grid">
              <NumField
                id="exc-days"
                label="Longest exception (days)"
                value={exceptionDays}
                step={1}
                min={1}
                max={730}
                onChange={(n) => set("exception_max_days", n)}
                hint={`Between 1 and 730. Default ${DEFAULT_EXCEPTION_MAX_DAYS}.`}
              />
            </div>
            {!exceptionDaysValid && <p className="hint text-bad">Longest exception must be a whole number of days between 1 and 730.</p>}
          </Card>
          <Card title="SOS rules">
            <p className="hint">
              A finding is SOS when any rule matches (all its conditions hold). Only confirmed findings can be SOS, and a rule cannot rely
              on severity alone: add an exploitation, exposure, environment or priority condition.
            </p>
            {rules.length === 0 && <p className="muted">No SOS rules: nothing will be flagged SOS.</p>}
            {rules.map((r, i) => (
              <div key={i} className="rule-card">
                <div className="form-grid">
                  <div className="field field-span">
                    <label htmlFor={`sos-${i}-name`}>Rule name</label>
                    <input id={`sos-${i}-name`} required value={r.name} onChange={(e) => setRule(i, { ...r, name: e.target.value })} />
                  </div>
                  <div className="field">
                    <label htmlFor={`sos-${i}-prio`}>Minimum priority</label>
                    <select
                      id={`sos-${i}-prio`}
                      value={r.min_priority ?? ""}
                      onChange={(e) => setRule(i, { ...r, min_priority: (e.target.value || undefined) as SOSRule["min_priority"] })}
                    >
                      <option value="">Any</option>
                      {PRIORITIES.map((pr) => (
                        <option key={pr} value={pr}>
                          {pr} or higher
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="field">
                    <label htmlFor={`sos-${i}-sev`}>Minimum severity</label>
                    <select id={`sos-${i}-sev`} value={r.min_severity ?? ""} onChange={(e) => setRule(i, { ...r, min_severity: e.target.value || undefined })}>
                      <option value="">Any</option>
                      {["critical", "high", "medium", "low"].map((s) => (
                        <option key={s} value={s}>
                          {s} or higher
                        </option>
                      ))}
                    </select>
                  </div>
                  <TriSelect id={`sos-${i}-kev`} label="Known exploited" value={r.known_exploited} onChange={(b) => setRule(i, { ...r, known_exploited: b })} />
                  <TriSelect id={`sos-${i}-prod`} label="Production" value={r.production} onChange={(b) => setRule(i, { ...r, production: b })} />
                  <TriSelect
                    id={`sos-${i}-exp`}
                    label="Internet exposed"
                    value={r.internet_exposed}
                    onChange={(b) => setRule(i, { ...r, internet_exposed: b })}
                    hint="“Yes” also matches unknown exposure."
                  />
                  <TriSelect id={`sos-${i}-fix`} label="Fix available" value={r.fix_available} onChange={(b) => setRule(i, { ...r, fix_available: b })} />
                </div>
                {admin && (
                  <button type="button" className="btn btn-sm btn-link-danger" onClick={() => set("sos_rules", rules.filter((_, j) => j !== i))}>
                    Remove rule
                  </button>
                )}
              </div>
            ))}
            {admin && (
              <button type="button" className="btn btn-sm" onClick={() => set("sos_rules", [...rules, { name: "", production: true, known_exploited: true }])}>
                Add SOS rule
              </button>
            )}
          </Card>
        </fieldset>
        <ErrorBox error={previewAct.error} title="Could not preview the change" />
        {dirty && previewed && preview && <PreviewCard pv={preview.data} />}
        <ErrorBox error={act.error} title="Policy not saved" />
        {saved && <Notice kind="success">Risk policy saved. Priorities are recalculated on the next notification cycle (within a few minutes).</Notice>}
        {admin && (
          <div className="form-actions bulkbar">
            <button type="button" className="btn" disabled={!dirty || !exceptionDaysValid || previewAct.pending || previewed} onClick={() => void runPreview()}>
              {previewAct.pending ? "Previewing…" : preview && !previewed ? "Preview again" : "Preview impact"}
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={act.pending || !dirty || !exceptionDaysValid || !previewed}
              title={dirty && !previewed ? "Preview the impact of these changes first" : undefined}
            >
              {act.pending ? "Saving…" : "Save policy"}
            </button>
            <button
              type="button"
              className="btn"
              disabled={!dirty || act.pending}
              onClick={() => {
                setP(structuredClone(res.data!.policy));
                setPreview(null);
                act.clear();
              }}
            >
              Discard changes
            </button>
            {dirty && <span className="muted small">{previewed ? "Previewed, not saved" : "Unsaved changes: preview them before saving"}</span>}
          </div>
        )}
      </form>
    </>
  );
}
