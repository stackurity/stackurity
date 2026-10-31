import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router";
import { api, type UpdateRelease, type UpdateStatus } from "../../api";
import { useAuth } from "../../auth";
import { useLoad } from "../../hooks";
import { Badge } from "../../components/Badge";
import { Markdown } from "../../components/Markdown";
import { Card, CodeBlock, ErrorBox, Loading, Notice, PageHeader, RelativeTime } from "../../components/ui";
import { plural } from "../../format";

const REPO = "https://github.com/stackurity/stackurity";
const CHANGELOG_URL = `${REPO}/blob/main/CHANGELOG.md`;
const UPGRADE_DOCS_URL = `${REPO}/blob/main/docs/install.md#upgrading`;

/** The running version as people read it: no leading "v". */
const shown = (v: string) => v.replace(/^v/, "");

function dateOnly(iso: string | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime()) || d.getFullYear() < 2000) return "";
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

/** Instance administration: releases newer than the running one. */
export function UpdatesPage() {
  const res = useLoad(() => api.get<UpdateStatus>("/updates"), []);
  const d = res.data;
  return (
    <>
      <PageHeader
        title="What's new"
        sub="Newer Stackurity releases. The server reads the public release list every 12 hours and sends nothing about itself."
        actions={
          <a className="btn" href={CHANGELOG_URL} target="_blank" rel="noopener noreferrer">
            Full changelog
          </a>
        }
      />
      <ErrorBox error={res.error} title="Could not load release information" />
      {!d && !res.error && <Loading />}
      {d && <UpdatesBody d={d} />}
    </>
  );
}

function UpdatesBody({ d }: { d: UpdateStatus }) {
  if (!d.enabled) {
    return (
      <Notice>
        The update check is turned off on this server (<code className="code">STACKURITY_UPDATE_CHECK=off</code>), so newer releases are not
        shown here. You run {shown(d.current)}. See the{" "}
        <a href={CHANGELOG_URL} target="_blank" rel="noopener noreferrer">
          changelog on GitHub
        </a>{" "}
        for what has been released.
      </Notice>
    );
  }
  if (!d.comparable) {
    return (
      <Notice>
        This is a development build ({d.current || "unknown version"}), so it is not compared with releases.
        {d.latest && <> The latest release is {d.latest}.</>}
      </Notice>
    );
  }
  if (!d.checked_at) {
    return (
      <Notice>
        No release check has completed yet. The server checks shortly after it starts and then every 12 hours; a server without internet access
        (or behind a proxy that blocks api.github.com) never completes one. You run {shown(d.current)}.
      </Notice>
    );
  }
  if (!d.update_available) {
    return (
      <Notice kind="success">
        You run the latest release ({shown(d.current)}). Last checked <RelativeTime iso={d.checked_at} />.
      </Notice>
    );
  }
  return (
    <>
      <Notice kind={d.security ? "warn" : "info"}>
        {d.security && <strong>This upgrade includes security fixes. </strong>}
        Stackurity {d.latest} is available; you run {shown(d.current)} ({plural(d.releases.length, "newer release")}). Last checked{" "}
        <RelativeTime iso={d.checked_at} />.
      </Notice>
      <Card title="How to upgrade">
        <p>
          <strong>Take a backup first.</strong> Downgrades are not supported: to roll back, you restore the backup taken before the upgrade.
          Migrations run automatically when the new version starts. Read the notes below for anything marked <em>Upgrading</em>.
        </p>
        <h3 className="md-h">Docker Compose</h3>
        <CodeBlock label="Docker Compose upgrade" text="docker compose pull && docker compose up -d" />
        <h3 className="md-h">Helm</h3>
        <p>
          Set the image tag (or chart version) to {d.latest} and run <code className="code">helm upgrade</code> with your usual values.
        </p>
        <p className="small">
          <a href={UPGRADE_DOCS_URL} target="_blank" rel="noopener noreferrer">
            Upgrading guide
          </a>{" "}
          ·{" "}
          <a href={CHANGELOG_URL} target="_blank" rel="noopener noreferrer">
            Full changelog
          </a>
        </p>
      </Card>
      {d.releases.map((r) => (
        <ReleaseCard key={r.version} r={r} />
      ))}
    </>
  );
}

function ReleaseCard({ r }: { r: UpdateRelease }) {
  const date = dateOnly(r.published_at);
  return (
    <Card
      title={
        <>
          Stackurity {r.version} {r.security && <Badge status="security" tone="crit" label="Security" />}
        </>
      }
      actions={
        r.url ? (
          <a className="btn btn-sm" href={r.url} target="_blank" rel="noopener noreferrer">
            On GitHub
          </a>
        ) : undefined
      }
    >
      {date && <p className="small muted">Released {date}</p>}
      {r.notes.trim() ? <Markdown source={r.notes} /> : <p className="muted">This release has no notes.</p>}
      {r.notes_truncated && (
        <p className="small muted">
          The notes are cut short here.{" "}
          {r.url && (
            <a href={r.url} target="_blank" rel="noopener noreferrer">
              Read them in full on GitHub
            </a>
          )}
        </p>
      )}
    </Card>
  );
}

// --- banner

const DISMISS_KEY = "stackurity.update.dismissed";
const SNOOZE_KEY = "stackurity.update.snoozed";
const SNOOZE_MS = 24 * 60 * 60 * 1000;

function readKey(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null; // storage unavailable (private mode, blocked)
  }
}

function writeKey(key: string, value: string) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // ignore: the banner then comes back on the next load
  }
}

function snoozed(version: string): boolean {
  try {
    const v = JSON.parse(readKey(SNOOZE_KEY) ?? "null") as { version?: string; until?: number } | null;
    return Boolean(v && v.version === version && typeof v.until === "number" && v.until > Date.now());
  } catch {
    return false;
  }
}

/**
 * A banner for instance admins when a newer release exists. An ordinary
 * update can be dismissed for that version. A security update cannot be
 * dismissed, only snoozed for 24 hours.
 */
export function UpdateBanner() {
  const { me } = useAuth();
  const { pathname } = useLocation();
  const admin = Boolean(me?.user?.instance_admin);
  const res = useLoad(() => (admin ? api.get<UpdateStatus>("/updates").catch(() => null) : Promise.resolve(null)), [admin]);
  const { reload } = res;
  useEffect(() => {
    if (!admin) return;
    const t = setInterval(reload, 60 * 60_000);
    return () => clearInterval(t);
  }, [admin, reload]);
  // Also hidden in memory, for browsers that refuse storage.
  const [hidden, setHidden] = useState<string | null>(null);

  const d = res.data;
  if (!d || !d.enabled || !d.update_available || !d.latest || pathname.startsWith("/updates")) return null;
  const latest = d.latest;
  const current = shown(d.current);
  if (hidden === latest) return null;

  if (d.security) {
    if (snoozed(latest)) return null;
    return (
      <div className="alert alert-error update-banner" role="alert">
        <span className="update-banner-text">
          <strong>Security update available.</strong> Stackurity {latest} fixes security issues. You run {current}.{" "}
          <Link to="/updates">What&apos;s new</Link>
        </span>
        <button
          type="button"
          className="btn btn-sm"
          onClick={() => {
            writeKey(SNOOZE_KEY, JSON.stringify({ version: latest, until: Date.now() + SNOOZE_MS }));
            setHidden(latest);
          }}
        >
          Remind me tomorrow
        </button>
      </div>
    );
  }

  if (readKey(DISMISS_KEY) === latest) return null;
  return (
    <div className="alert alert-info update-banner" role="status">
      <span className="update-banner-text">
        Stackurity {latest} is available. You run {current}. <Link to="/updates">What&apos;s new</Link>
      </span>
      <button
        type="button"
        className="btn btn-sm"
        onClick={() => {
          writeKey(DISMISS_KEY, latest);
          setHidden(latest);
        }}
      >
        Dismiss<span className="sr-only"> the notice for {latest}</span>
      </button>
    </div>
  );
}
