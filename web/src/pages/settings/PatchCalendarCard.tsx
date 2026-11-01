import { DEFAULT_PATCH_CALENDAR, type PatchCalendar, type RiskPolicy } from "../../api";
import { Card } from "../../components/ui";

/** Today's date (year, month 1–12, day) in a time zone; UTC when the zone is unknown. */
function todayIn(timeZone: string): [number, number, number] {
  let parts: string;
  try {
    parts = new Intl.DateTimeFormat("en-CA", { timeZone, year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());
  } catch {
    parts = new Date().toISOString().slice(0, 10);
  }
  const [y, m, d] = parts.split("-").map(Number);
  return [y, m, d];
}

/** The first window day after today, as the server computes it (risk.PatchCalendar.NextWindow). */
function nextWindow(c: PatchCalendar, prod: boolean): Date {
  const offset = c.test_days_after_patch_tuesday + (prod ? c.prod_days_after_test : 0);
  const [y, m, d] = todayIn(c.timezone || "UTC");
  const today = Date.UTC(y, m - 1, d);
  for (let k = -2; ; k++) {
    const first = new Date(Date.UTC(y, m - 1 + k, 1));
    const tuesday = 1 + ((2 - first.getUTCDay() + 7) % 7) + 7;
    const day = new Date(Date.UTC(first.getUTCFullYear(), first.getUTCMonth(), tuesday + offset));
    if (day.getTime() > today) return day;
  }
}

const showDay = (d: Date) => d.toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });

/** Settings → Risk policy: whether fix deadlines come from the SLA or a monthly patch calendar. */
export function PatchCalendarCard({
  policy,
  onChange,
}: {
  policy: RiskPolicy;
  onChange: (k: "due_dates" | "patch_calendar", v: RiskPolicy["due_dates"] | PatchCalendar) => void;
}) {
  const calendar = policy.due_dates === "patch_calendar";
  const c = { ...DEFAULT_PATCH_CALENDAR, ...policy.patch_calendar };
  const setCal = (patch: Partial<PatchCalendar>) => onChange("patch_calendar", { ...c, ...patch });
  const whole = (v: string) => Math.round(Number(v) || 0);
  return (
    <Card title="Due dates">
      <div className="form-grid">
        <div className="field field-span">
          <label htmlFor="due-dates">Fix deadlines</label>
          <select
            id="due-dates"
            value={calendar ? "patch_calendar" : "sla"}
            onChange={(e) => onChange("due_dates", e.target.value === "patch_calendar" ? "patch_calendar" : undefined)}
          >
            <option value="sla">Days after first seen, per priority (the deadlines above)</option>
            <option value="patch_calendar">Next patch window, except urgent findings</option>
          </select>
          <p className="hint">
            {calendar
              ? "P1, SOS and known exploited findings keep the deadlines above. The rest are due when their asset's next patch window " +
                "after first seen ends. An asset is test (tag patch-window:test, or a dev, test, uat, staging or qa environment or " +
                "name) or production (tag patch-window:prod, or anything else)."
              : "Each finding is due a fixed number of days after its asset first had it."}
          </p>
        </div>
        {calendar && (
          <>
            <div className="field">
              <label htmlFor="pc-test">Test window: days after Patch Tuesday</label>
              <input
                id="pc-test"
                className="num-input"
                type="number"
                min={0}
                max={20}
                step={1}
                value={String(c.test_days_after_patch_tuesday)}
                onChange={(e) => setCal({ test_days_after_patch_tuesday: whole(e.target.value) })}
              />
              <p className="hint">Patch Tuesday is the second Tuesday of the month; 1 is the Wednesday after it. 0 to 20.</p>
            </div>
            <div className="field">
              <label htmlFor="pc-prod">Production window: days after the test window</label>
              <input
                id="pc-prod"
                className="num-input"
                type="number"
                min={0}
                max={28}
                step={1}
                value={String(c.prod_days_after_test)}
                onChange={(e) => setCal({ prod_days_after_test: whole(e.target.value) })}
              />
              <p className="hint">0 to 28.</p>
            </div>
            <div className="field">
              <label htmlFor="pc-tz">Time zone</label>
              <input id="pc-tz" value={c.timezone} placeholder="UTC" onChange={(e) => setCal({ timezone: e.target.value })} />
              <p className="hint">Each window is one day in this time zone, e.g. Europe/Berlin.</p>
            </div>
            <p className="hint field-span">
              Next windows: test {showDay(nextWindow(c, false))}, production {showDay(nextWindow(c, true))}.
            </p>
          </>
        )}
      </div>
    </Card>
  );
}
