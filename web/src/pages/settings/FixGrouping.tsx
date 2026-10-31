import { useState } from "react";
import { Link } from "react-router";
import { api, type FixGrouping } from "../../api";
import { useAuth } from "../../auth";
import { useAction, useLoad } from "../../hooks";
import { Card, ErrorBox, Loading, Notice, PageHeader } from "../../components/ui";

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
        <Card title="Fix lists">
          <fieldset className="field" disabled={!can("admin") || act.pending}>
            <legend>Show the same fix in several places as</legend>
            <ul className="choice-list">
              {CHOICES.map((c) => (
                <li key={c.value}>
                  <label className="choice">
                    <input type="radio" name="fix-grouping" checked={current === c.value} onChange={() => void choose(c.value)} />
                    <span>
                      <strong>{c.label}</strong>
                      {c.value === "fix" && <span className="muted"> (default)</span>}
                      <span className="hint"> {c.about}</span>
                    </span>
                  </label>
                </li>
              ))}
            </ul>
          </fieldset>
          {!can("admin") && <p className="hint">Only an admin can change this.</p>}
          {saved && <Notice kind="success">Saved. Fix lists now use this grouping.</Notice>}
        </Card>
      )}
    </>
  );
}
