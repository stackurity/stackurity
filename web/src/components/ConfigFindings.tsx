import { useState } from "react";
import { Link } from "react-router";
import {
  api,
  type ConfigCategory,
  type ConfigFinding,
  type ConfigFindingList,
  type ConfigSummary,
} from "../api";
import { useAuth } from "../auth";
import { configEmpty, type ConfigViewName } from "../emptyCopy";
import { useAction, useLoad } from "../hooks";
import { SeverityBadge } from "./Badge";
import { promptText } from "./ConfirmDialog";
import { Table, type Column } from "./Table";
import {
  EmptyState,
  ErrorBox,
  Loading,
  Notice,
  Pager,
  RelativeTime,
  StatTile,
  Tabs,
} from "./ui";

/**
 * Risky settings (config findings): AI coding-agent hooks that download and
 * run code, SSH keys and settings that give root an unrestricted shell, and
 * GitHub Actions that run third-party code by a movable tag. Each row says
 * in one line why it is a risk and what to change in the file.
 */

export const CATEGORY_LABEL: Record<ConfigCategory, string> = {
  agent_hook: "AI agent hooks",
  ssh: "SSH access",
  ci: "GitHub Actions",
};

const VIEW_QUERY: Record<
  ConfigViewName,
  { status: string; severity?: string }
> = {
  attention: { status: "open", severity: "high,medium" },
  listed: { status: "open", severity: "low,info" },
  resolved: { status: "resolved" },
};

const VIEW_LABEL: Record<ConfigViewName, string> = {
  attention: "Needs a look",
  listed: "Listed only",
  resolved: "Resolved",
};

const VIEW_HINT: Record<ConfigViewName, string> = {
  attention:
    "High: a hook or workflow that runs code someone else controls, today. Medium: access that is wider than it needs to be, such as a CI key with a full root shell. Only high ones raise an incident.",
  listed:
    "Low and information only: third-party actions not pinned to a commit, GitHub's own actions by tag, and root keys with no restriction (normal for an administrator's own key). They never alert.",
  resolved: "Settings a complete check no longer finds, and those dismissed.",
};

const LIMIT = 50;

function where(f: ConfigFinding): string {
  return f.line > 0 ? `${f.path}:${f.line}` : f.path;
}

function ConfigTable({
  items,
  showAsset,
  onChanged,
}: {
  items: ConfigFinding[];
  showAsset: boolean;
  onChanged: () => void;
}) {
  const { canAct } = useAuth();
  const act = useAction();
  const security = canAct("security");

  const dismiss = async (f: ConfigFinding) => {
    const note = await promptText({
      title: `Dismiss ${f.title} in ${where(f)}?`,
      message:
        "It stays dismissed whatever later checks see. Dismiss a setting that is meant to be there, and say why.",
      label: "Note (why it is meant to be there)",
      action: "Dismiss",
      allowEmpty: true,
    });
    if (note === null) return;
    if (
      await act.run(() =>
        api.post(`/config-findings/${f.id}/dismiss`, { note }),
      )
    )
      onChanged();
  };
  const reopen = async (f: ConfigFinding) => {
    if (await act.run(() => api.post(`/config-findings/${f.id}/undismiss`)))
      onChanged();
  };

  const cols: Column<ConfigFinding>[] = [
    {
      key: "severity",
      header: "Severity",
      cell: (f) => <SeverityBadge severity={f.severity} />,
    },
    {
      key: "what",
      header: "Setting",
      cell: (f) => (
        <>
          <strong>{f.title}</strong>
          <div className="small muted">
            {CATEGORY_LABEL[f.category] ?? f.category}
          </div>
          {f.subject && <div className="mono small break">{f.subject}</div>}
        </>
      ),
    },
    ...(showAsset
      ? [
          {
            key: "asset",
            header: "Asset",
            cell: (f: ConfigFinding) => (
              <Link to={`/assets/${f.asset_id}?tab=config`}>
                {f.asset_name}
              </Link>
            ),
          },
        ]
      : []),
    {
      key: "why",
      header: "Why and what to change",
      cell: (f) => (
        <>
          <span className="mono small break">{where(f)}</span>
          <p className="small">{f.why}</p>
          <p className="small">
            <strong>Fix:</strong> {f.fix}
            {f.doc_url && (
              <>
                {" "}
                <a href={f.doc_url} target="_blank" rel="noreferrer">
                  How-to
                </a>
              </>
            )}
          </p>
        </>
      ),
    },
    {
      key: "seen",
      header: "Found",
      cell: (f) =>
        f.status === "open" ? (
          <RelativeTime iso={f.first_seen} />
        ) : (
          <div className="small muted">
            {f.resolution === "dismissed" ? "Dismissed" : "Gone"}{" "}
            <RelativeTime iso={f.resolved_at} />
            {f.resolution_note && <div>{f.resolution_note}</div>}
          </div>
        ),
    },
    ...(security
      ? [
          {
            key: "actions",
            header: "",
            cell: (f: ConfigFinding) =>
              f.status === "open" ? (
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => void dismiss(f)}
                >
                  Dismiss…
                </button>
              ) : f.resolution === "dismissed" ? (
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => void reopen(f)}
                >
                  Open again
                </button>
              ) : null,
          },
        ]
      : []),
  ];
  return (
    <>
      <ErrorBox
        error={act.error}
        title="Could not change the setting's state"
      />
      <Table
        caption="Risky settings"
        columns={cols}
        rows={items}
        rowKey={(f) => f.id}
      />
    </>
  );
}

function SummaryStrip({ s }: { s: ConfigSummary }) {
  const high = s.by_severity.high ?? 0;
  const medium = s.by_severity.medium ?? 0;
  return (
    <div className="tiles" role="group" aria-label="Open risky settings">
      <StatTile
        label="High"
        value={high.toLocaleString()}
        tone={high > 0 ? "bad" : "good"}
        sub="Runs code someone else controls; alerts"
      />
      <StatTile
        label="Medium"
        value={medium.toLocaleString()}
        tone={medium > 0 ? "warn" : undefined}
        sub="Wider access than needed"
      />
      <StatTile
        label="Listed only"
        value={(
          (s.by_severity.low ?? 0) + (s.by_severity.info ?? 0)
        ).toLocaleString()}
        sub="Low and information only"
      />
      <StatTile
        label="Assets checked"
        value={s.scanned_assets.toLocaleString()}
        sub="Servers and repositories"
      />
    </div>
  );
}

/** Risky settings for the whole organisation or one asset, in three views. */
export function ConfigFindingsView({ assetId }: { assetId?: number }) {
  const { can } = useAuth();
  const [view, setView] = useState<ConfigViewName>("attention");
  const [category, setCategory] = useState("");
  const [offset, setOffset] = useState(0);
  const path = assetId
    ? `/assets/${assetId}/config-findings`
    : "/config-findings";
  const res = useLoad(
    () =>
      api.get<ConfigFindingList>(path, {
        ...VIEW_QUERY[view],
        ...(category ? { category } : {}),
        limit: LIMIT,
        offset,
      }),
    [path, view, category, offset],
  );
  const summary = useLoad(
    () =>
      api.get<ConfigSummary>(
        "/config-findings/summary",
        assetId ? { asset_id: assetId } : {},
      ),
    [assetId, res.data],
  );
  const scans = res.data?.scans;
  return (
    <>
      {assetId && scans && scans.length === 0 && (
        <Notice kind="warn">
          This asset's settings have not been checked, so an empty list does not
          mean there are none. Agents, repository integrations and{" "}
          <span className="mono">stackurity scan</span> from this version on
          check them.
        </Notice>
      )}
      {scans
        ?.filter((s) => !s.complete)
        .map((s) => (
          <Notice key={s.collector_id} kind="warn">
            The last check by {s.collector_id} (
            <RelativeTime iso={s.scanned_at} />) was incomplete
            {s.reason ? `: ${s.reason}` : ""}. Settings it could not read are
            not listed, and none were resolved.
          </Notice>
        ))}
      {summary.data && <SummaryStrip s={summary.data} />}
      <Tabs<ConfigViewName>
        label="Risky setting views"
        value={view}
        onChange={(v) => {
          setView(v);
          setOffset(0);
        }}
        tabs={(["attention", "listed", "resolved"] as ConfigViewName[]).map(
          (v) => ({ id: v, label: VIEW_LABEL[v] }),
        )}
      />
      <p className="hint">{VIEW_HINT[view]}</p>
      <div className="form-grid">
        <div className="field">
          <label htmlFor="config-category">Kind</label>
          <select
            id="config-category"
            value={category}
            onChange={(e) => {
              setCategory(e.target.value);
              setOffset(0);
            }}
          >
            <option value="">Any kind</option>
            {(Object.keys(CATEGORY_LABEL) as ConfigCategory[]).map((c) => (
              <option key={c} value={c}>
                {CATEGORY_LABEL[c]}
              </option>
            ))}
          </select>
        </div>
      </div>
      <ErrorBox error={res.error} title="Could not load risky settings" />
      {!res.data && !res.error && <Loading />}
      {res.data &&
        res.data.items.length === 0 &&
        (category ? (
          <p className="muted">No risky settings of this kind.</p>
        ) : (
          <EmptyState
            {...configEmpty(
              view,
              assetId ? undefined : summary.data?.scanned_assets,
              can("admin"),
            )}
          />
        ))}
      {res.data && res.data.items.length > 0 && (
        <>
          <ConfigTable
            items={res.data.items}
            showAsset={!assetId}
            onChanged={res.reload}
          />
          <Pager
            total={res.data.total}
            limit={LIMIT}
            offset={offset}
            onChange={setOffset}
          />
        </>
      )}
    </>
  );
}
