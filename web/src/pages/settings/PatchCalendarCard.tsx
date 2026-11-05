import { DEFAULT_PATCH_CALENDAR, type PatchCalendar, type RiskPolicy } from "../../api";
import { Card, ChoiceCards, GoodToKnow, OptionBadge, SettingRow } from "../../components/ui";

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
    <Card title="Due dates" description="How each finding's fix deadline is set: a number of days after it was found, or your monthly patch window.">
      <SettingRow title="Fix deadlines" description="Pick the patch window if your team installs updates on a monthly schedule, so routine fixes are due on the day you would apply them anyway.">
        <ChoiceCards
          name="due-dates"
          legend="Fix deadlines"
          value={calendar ? "patch_calendar" : "sla"}
          onChange={(v) => onChange("due_dates", v === "patch_calendar" ? "patch_calendar" : undefined)}
          options={[
            {
              value: "sla",
              label: "Days after first seen, per priority (the deadlines above)",
              description: "Each finding is due a fixed number of days after its asset first had it.",
              badge: <OptionBadge tone="muted">Default</OptionBadge>,
            },
            {
              value: "patch_calendar",
              label: "Next patch window, except urgent findings",
              description:
                "P1, SOS and known exploited findings keep the deadlines above. The rest are due when their asset's next patch window after first seen ends.",
            },
          ]}
        />
      </SettingRow>
      {calendar && (
        <>
          <SettingRow
            title="Patch windows"
            description="Each month has a test window and then a production window, each one day long. Patch Tuesday is the second Tuesday of the month, when Microsoft and many vendors release updates."
          >
            <div className="form-grid">
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
                <p className="hint">1 is the Wednesday after Patch Tuesday. 0 to 20.</p>
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
            </div>
          </SettingRow>
          <GoodToKnow>
            <ul>
              <li>
                Next windows: test {showDay(nextWindow(c, false))}, production {showDay(nextWindow(c, true))}.
              </li>
              <li>
                An asset uses the test window when it has the tag <code>patch-window:test</code>, or a dev, test, uat, staging or qa environment or
                name. Everything else (or the tag <code>patch-window:prod</code>) uses the production window.
              </li>
            </ul>
          </GoodToKnow>
        </>
      )}
    </Card>
  );
}
