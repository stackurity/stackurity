import { useState } from "react";
import { api, type SecondCheckHistory, type SecondCheckVerdict } from "../api";
import { useLoad } from "../hooks";
import { SECOND_CHECK } from "../secondCheck";
import { Badge } from "./Badge";
import { ErrorBox, Loading, RelativeTime } from "./ui";

/**
 * The independent second check of a leaked key or a risky setting: its
 * verdict as a chip, the one-sentence reason under it, and, on request, how
 * the verdict was reached over time (the append-only history).
 */

export function SecondCheckBadge({ check }: { check: SecondCheckVerdict | null }) {
  if (!check) {
    return <Badge status="second-check-pending" tone="muted" label="Second check pending" title="Checked within a minute of each scan." />;
  }
  const s = SECOND_CHECK[check.verdict];
  return <Badge status={`second-check-${check.verdict}`} tone={s.tone} label={s.label} title={s.hint} />;
}

/** The verdict, its reason and a link to its history, for a table cell. */
export function SecondCheckCell({ check, historyPath }: { check: SecondCheckVerdict | null; historyPath: string }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="small">
      <SecondCheckBadge check={check} />
      {check && <div className="muted">{check.reason}</div>}
      {check && (
        <details onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}>
          <summary>How this was reached</summary>
          {open && <SecondCheckHistoryList path={historyPath} />}
        </details>
      )}
    </div>
  );
}

function SecondCheckHistoryList({ path }: { path: string }) {
  const res = useLoad(() => api.get<SecondCheckHistory>(path), [path]);
  if (res.error) return <ErrorBox error={res.error} title="Could not load the second check's history" />;
  if (!res.data) return <Loading />;
  return (
    <ol className="second-check-history">
      {res.data.items.map((v) => (
        <li key={v.id ?? v.checked_at}>
          <RelativeTime iso={v.checked_at} />: <strong>{SECOND_CHECK[v.verdict]?.label ?? v.verdict}</strong>. {v.reason}{" "}
          <span className="muted">(rules {v.checker})</span>
        </li>
      ))}
    </ol>
  );
}
