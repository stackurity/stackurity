import { useState } from "react";
import { Link } from "react-router";
import { api, type FixGrouping } from "../../api";
import { useAuth } from "../../auth";
import { useAction, useLoad } from "../../hooks";
import { Card, CardFooter, ChoiceCards, ErrorBox, Loading, OptionBadge, PageHeader, SettingRow } from "../../components/ui";

const CHOICES: { value: FixGrouping; label: string; about: string }[] = [
  {
    value: "fix",
    label: "One card per fix",
    about:
      "The same upgrade in several places (jquery 3.3.1 → 3.5.0 in two apps, or on ten servers) is one card that lists every place. Counts add up the places; distinct vulnerabilities are counted once.",
  },
  {
    value: "asset",
    label: "One card per asset",
    about: "Each server, application or repository gets its own card for each fix, even when the same upgrade is needed elsewhere.",
  },
];

/** Settings, Fix grouping: how Fixes shows the same fix in several places. */
export function FixGroupingPage() {
  const { can } = useAuth();
  const res = useLoad(() => api.get<{ fix_grouping: FixGrouping }>("/settings/fix-grouping"), []);
  const act = useAction();
  const [saved, setSaved] = useState(false);
  const current = res.data?.fix_grouping;
  const choose = async (v: FixGrouping) => {
    setSaved(false);
    const r = await act.run(() => api.put<{ fix_grouping: FixGrouping }>("/settings/fix-grouping", { fix_grouping: v }));
    if (r) {
      setSaved(true);
      res.reload();
    }
  };
  return (
    <>
      <PageHeader
        title="Fix grouping"
        sub={
          <>
            How <Link to="/fixes">Fixes</Link> and the Dashboard list a fix that is needed in more than one place, for everyone in this workspace.
          </>
        }
      />
      <ErrorBox error={res.error} title="Could not load the setting" />
      <ErrorBox error={act.error} title="Could not save the setting" />
      {!res.data && !res.error && <Loading />}
      {current && (
        <Card
          title="Same fix in several places"
          description="When one upgrade fixes the same problem in several places (the same library in two apps, or the same package on ten servers), choose whether Fixes shows it once or once per place."
        >
          <SettingRow
            title="Show the same fix in several places as"
            description="One card per fix keeps the list short and suits one team patching everything. One card per asset suits teams that each own their own servers or apps."
          >
            <fieldset className="choice-cards-set" disabled={!can("admin") || act.pending}>
              <ChoiceCards
                name="fix-grouping"
                legend="Show the same fix in several places as"
                value={current}
                onChange={(v) => void choose(v)}
                options={CHOICES.map((c) => ({
                  value: c.value,
                  label: c.label,
                  description: c.about,
                  badge: c.value === "fix" ? <OptionBadge tone="muted">Default</OptionBadge> : undefined,
                }))}
              />
            </fieldset>
          </SettingRow>
          <CardFooter
            status={
              saved
                ? "Saved. Fix lists now use this grouping."
                : can("admin")
                  ? "Applies to everyone in this workspace. Saved as soon as you pick one."
                  : "Only an admin can change this."
            }
          />
        </Card>
      )}
    </>
  );
}
