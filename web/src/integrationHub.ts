/**
 * The Integrations page in words and numbers: each connected integration's
 * status, the health summary above the cards, what a channel receives, its
 * scope and how many of each kind are connected. The components in
 * components/IntegrationCards.tsx only lay these out, so node --test can
 * check the logic without a browser.
 */
import { eventsOf, type Channel, type Integration, type Priority, type Project, type Route } from "./api.ts";

/** Healthy: worked last time. Failing: the last try failed. Paused: turned off. Never used: on, but nothing sent or read yet. */
export type HubStatus = "healthy" | "failing" | "paused" | "never";

export const STATUS_WORD: Record<HubStatus, string> = {
  healthy: "Healthy",
  failing: "Failing",
  paused: "Paused",
  never: "Never used",
};

/** Alert channels (they deliver messages), data sources (they collect), servers with the agent (they report). */
export type HubGroup = "alerts" | "sources" | "servers";

export const GROUP_TITLE: Record<HubGroup, string> = {
  alerts: "Alerts and tickets",
  sources: "Data sources",
  servers: "Servers with the agent",
};

/** The label of the card's "last time it worked" line. */
export const LAST_OK_LABEL: Record<HubGroup, string> = {
  alerts: "Last successful delivery",
  sources: "Last successful run",
  servers: "Last report",
};

export interface Scope {
  label: string;
  to?: string;
}

/** One connected integration as a card shows it. */
export interface HubItem {
  key: string;
  group: HubGroup;
  /** IntegrationIcon kind. */
  kind: string;
  name: string;
  kindLabel: string;
  target: string;
  targetMono?: boolean;
  enabled: boolean;
  ok: string | null;
  error: string;
  /** Where Open goes. */
  to: string;
  scope: Scope;
  /** Channels only: what its rules send, in a few words. */
  receives?: Receives;
  channelId?: number;
  sourceId?: number;
}

export function statusOf(x: Pick<HubItem, "enabled" | "ok" | "error">): HubStatus {
  if (!x.enabled) return "paused";
  if (x.error) return "failing";
  if (!x.ok) return "never";
  return "healthy";
}

/** Status dot tone: colour is for status only. */
export const STATUS_TONE: Record<HubStatus, "good" | "bad" | "muted" | "warn"> = {
  healthy: "good",
  failing: "bad",
  paused: "muted",
  never: "warn",
};

const STATUS_ORDER: Record<HubStatus, number> = { failing: 0, never: 1, healthy: 2, paused: 3 };

/** Failing first, then never used, healthy and paused; by name within each. */
export function sortItems(items: HubItem[]): HubItem[] {
  return [...items].sort((a, b) => STATUS_ORDER[statusOf(a)] - STATUS_ORDER[statusOf(b)] || a.name.localeCompare(b.name));
}

export interface HubSummary {
  connected: number;
  healthy: number;
  failing: number;
  paused: number;
  never: number;
  /** Channels and sources apart (servers count once per row). */
  alerts: number;
  sources: number;
  servers: number;
  /** The newest successful delivery of any alert channel. */
  lastDelivery: string | null;
  lastDeliveryBy: string;
}

export function summarise(items: HubItem[]): HubSummary {
  const s: HubSummary = { connected: items.length, healthy: 0, failing: 0, paused: 0, never: 0, alerts: 0, sources: 0, servers: 0, lastDelivery: null, lastDeliveryBy: "" };
  for (const i of items) {
    s[statusOf(i)]++;
    s[i.group]++;
    if (i.group === "alerts" && i.ok && (!s.lastDelivery || Date.parse(i.ok) > Date.parse(s.lastDelivery))) {
      s.lastDelivery = i.ok;
      s.lastDeliveryBy = i.name;
    }
  }
  return s;
}

export type StatusFilter = HubStatus | "all";

export function parseFilter(v: string | null): StatusFilter {
  return v === "healthy" || v === "failing" || v === "paused" || v === "never" ? v : "all";
}

export function filterItems(items: HubItem[], f: StatusFilter): HubItem[] {
  return f === "all" ? items : items.filter((i) => statusOf(i) === f);
}

/** "P1" or "P1–P3": a lowest priority as the range it sends. */
export function priorityRange(lowest: Priority | string | undefined, fallback: Priority): string {
  const p = lowest || fallback;
  return p === "P1" ? "P1" : `P1–${p}`;
}

/** One rule in a few words: "Urgent P1–P2 · daily summary · SOS only". */
export function ruleSummary(r: Route): string {
  const ev = eventsOf(r);
  const parts: string[] = [];
  if (ev.includes("urgent")) parts.push(`Urgent ${priorityRange(r.min_priority, "P1")}`);
  if (ev.includes("new_issues")) parts.push(!r.new_min_priority || r.new_min_priority === "P4" ? "All new issues" : `New ${priorityRange(r.new_min_priority, "P4")}`);
  if (ev.includes("daily_summary")) parts.push("daily summary");
  if (ev.includes("weekly_summary")) parts.push("weekly summary");
  const other = ev.filter((e) => e === "regressed" || e === "overdue" || e === "connected" || e === "problems").length;
  if (parts.length === 0 && other) parts.push(other === 1 ? "1 kind of update" : `${other} kinds of update`);
  if (parts.length === 0) return "Nothing";
  if (r.sos_only) parts.push("SOS only");
  if (r.environments?.length) parts.push(`${r.environments.join(", ")} only`);
  if (r.project_ids?.length) parts.push(r.project_ids.length === 1 ? "1 project" : `${r.project_ids.length} projects`);
  const s = parts.join(" · ");
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export interface Receives {
  text: string;
  /** One line per rule, for the tooltip when there are several. */
  rules: string[];
  /** No rule sends anything to it. */
  none: boolean;
}

/** What a channel receives, from the rules that use it. */
export function receivesOf(channelId: number, routes: Route[]): Receives {
  const mine = routes.filter((r) => r.channel_id === channelId);
  const on = mine.filter((r) => r.enabled);
  if (mine.length === 0) return { text: "Nothing yet: no rule sends to it", rules: [], none: true };
  if (on.length === 0) return { text: mine.length === 1 ? "Its rule is turned off" : "All its rules are turned off", rules: [], none: true };
  const rules = on.map((r) => `${r.name}: ${ruleSummary(r)}`);
  if (on.length === 1) return { text: ruleSummary(on[0]), rules, none: false };
  return { text: `${on.length} rules: ${ruleSummary(on[0])}, and more`, rules, none: false };
}

/** Organisation, or the project or asset the channel belongs to. */
export function scopeOf(c: Pick<Channel, "owner_project_id" | "owner_asset_id">, projects: Pick<Project, "id" | "name">[]): Scope {
  if (c.owner_asset_id) return { label: `Asset #${c.owner_asset_id}`, to: `/assets/${c.owner_asset_id}` };
  if (c.owner_project_id) {
    const p = projects.find((x) => x.id === c.owner_project_id);
    return { label: `Project ${p ? p.name : `#${c.owner_project_id}`}`, to: `/projects/${c.owner_project_id}` };
  }
  return { label: "Organisation" };
}

/** The catalogue card a data source counts towards ("Connected (2)"). */
export function sourceCatalogueKey(i: Pick<Integration, "kind" | "config">): string {
  if (i.kind === "git_repository") return "git";
  if (i.kind === "github_app") return "github";
  if (i.kind === "gitlab") return "gitlab";
  if (i.kind === "container_image" || i.kind === "container_registry") return "container";
  if (i.kind === "plugin") {
    const p = String(i.config?.plugin ?? "");
    if (p.startsWith("aws")) return "aws";
    if (p.startsWith("gcp") || p.startsWith("google")) return "gcp";
    if (p.startsWith("azure")) return "azure";
    if (p.includes("kube")) return "kubernetes";
    return "plugin";
  }
  return i.kind;
}

/** How many of each catalogue card are connected: channel kinds, source keys, and servers by OS. */
export function connectedCounts(channels: Pick<Channel, "kind">[], sources: Pick<Integration, "kind" | "config">[], servers: { linux: number; windows: number }): Record<string, number> {
  const n: Record<string, number> = {};
  const add = (k: string, by = 1) => {
    if (by > 0) n[k] = (n[k] ?? 0) + by;
  };
  for (const c of channels) add(c.kind);
  for (const s of sources) add(sourceCatalogueKey(s));
  add("server", servers.linux);
  add("windows", servers.windows);
  return n;
}
