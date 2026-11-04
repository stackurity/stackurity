import { DEFAULT_UNMAINTAINED_MONTHS, MAX_UNMAINTAINED_MONTHS, MIN_UNMAINTAINED_MONTHS, type RiskPolicy } from "../../api";
import { Card } from "../../components/ui";

/** The months a policy applies: its own value, or the default when it leaves it out. */
export function unmaintainedMonths(p: RiskPolicy): number {
  return p.unmaintained_months || DEFAULT_UNMAINTAINED_MONTHS;
}

/** Whether a policy's cutoff is one the server accepts: a whole number of months in range. */
export function unmaintainedValid(p: RiskPolicy): boolean {
  const n = unmaintainedMonths(p);
  return Number.isInteger(n) && n >= MIN_UNMAINTAINED_MONTHS && n <= MAX_UNMAINTAINED_MONTHS;
}

/** Settings → Risk policy: when the advice for issues with no fixed version calls a package unmaintained. */
export function UnmaintainedCard({ policy, onChange }: { policy: RiskPolicy; onChange: (months: number) => void }) {
  const months = unmaintainedMonths(policy);
  return (
    <Card title="Issues with no fix">
      <p className="hint">
        When an issue has no fixed version, How to fix says a package is unmaintained (a fix is unlikely) when its maintainers deprecated
        it or it has had no release for this long.
      </p>
      <div className="form-grid">
        <div className="field">
          <label htmlFor="unmaintained-months">Treat a package as unmaintained after (months without a release)</label>
          <input
            id="unmaintained-months"
            type="number"
            inputMode="numeric"
            step={1}
            min={MIN_UNMAINTAINED_MONTHS}
            max={MAX_UNMAINTAINED_MONTHS}
            value={String(months)}
            aria-describedby="unmaintained-months-hint"
            onChange={(e) => onChange(Math.round(Number(e.target.value)) || 0)}
          />
          <p id="unmaintained-months-hint" className="hint">
            Between {MIN_UNMAINTAINED_MONTHS} and {MAX_UNMAINTAINED_MONTHS}. Default {DEFAULT_UNMAINTAINED_MONTHS}. Takes effect when the
            action plan is next rebuilt, within about a minute.
          </p>
        </div>
      </div>
      {!unmaintainedValid(policy) && (
        <p className="hint text-bad">
          Months without a release must be a whole number between {MIN_UNMAINTAINED_MONTHS} and {MAX_UNMAINTAINED_MONTHS}.
        </p>
      )}
    </Card>
  );
}
