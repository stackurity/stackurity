import { test } from "node:test";
import assert from "node:assert/strict";
import {
  connectedCounts,
  credentialNote,
  lastDeliveryOf,
  filterItems,
  parseFilter,
  priorityRange,
  receivesOf,
  ruleSummary,
  scopeOf,
  sortItems,
  sourceCatalogueKey,
  statusOf,
  summarise,
  type HubItem,
} from "./integrationHub.ts";
import type { Integration, Route } from "./api.ts";

const item = (over: Partial<HubItem>): HubItem => ({
  key: over.name ?? "x",
  group: "alerts",
  kind: "slack",
  name: "x",
  kindLabel: "Slack",
  target: "",
  enabled: true,
  ok: null,
  error: "",
  to: "/integrations/channels/1",
  scope: { label: "Organisation" },
  ...over,
});

const route = (over: Partial<Route>): Route =>
  ({
    id: 1,
    name: "Default",
    channel_id: 7,
    enabled: true,
    min_priority: "P1",
    sos_only: false,
    kinds: null,
    environments: null,
    team_ids: null,
    escalation: false,
    send_resolved: false,
    quiet_start: "",
    quiet_end: "",
    timezone: "UTC",
    max_per_hour: 0,
    mode: "urgent_only",
    summary_time: "09:00",
    summary_day: "monday",
    events: ["urgent"],
    ...over,
  }) as Route;

test("statusOf: paused beats failing, failing beats never used", () => {
  assert.equal(statusOf({ enabled: false, ok: null, error: "boom" }), "paused");
  assert.equal(statusOf({ enabled: true, ok: "2026-11-01T00:00:00Z", error: "boom" }), "failing");
  assert.equal(statusOf({ enabled: true, ok: null, error: "" }), "never");
  assert.equal(statusOf({ enabled: true, ok: "2026-11-01T00:00:00Z", error: "" }), "healthy");
});

test("summarise counts each status and takes the newest delivery of an alert channel only", () => {
  const items = [
    item({ name: "a", ok: "2026-11-05T10:00:00Z" }),
    item({ name: "b", ok: "2026-11-06T08:00:00Z" }),
    item({ name: "c", error: "401", ok: "2026-11-06T09:00:00Z" }),
    item({ name: "d", enabled: false }),
    item({ name: "src", group: "sources", ok: "2026-11-06T11:00:00Z" }),
    item({ name: "hosts", group: "servers" }),
  ];
  const s = summarise(items);
  assert.equal(s.connected, 6);
  assert.equal(s.healthy, 3);
  assert.equal(s.failing, 1);
  assert.equal(s.paused, 1);
  assert.equal(s.never, 1);
  assert.deepEqual([s.alerts, s.sources, s.servers], [4, 1, 1]);
  // A failing channel's last success still counts; a source's run is not a delivery.
  assert.equal(s.lastDelivery, "2026-11-06T09:00:00Z");
  assert.equal(s.lastDeliveryBy, "c");
});

test("summarise of nothing", () => {
  const s = summarise([]);
  assert.equal(s.connected, 0);
  assert.equal(s.lastDelivery, null);
});

test("sortItems puts failing first, then never used, healthy, paused, by name", () => {
  const out = sortItems([
    item({ name: "zz", ok: "2026-11-01T00:00:00Z" }),
    item({ name: "paused", enabled: false }),
    item({ name: "new" }),
    item({ name: "broken", error: "x" }),
    item({ name: "aa", ok: "2026-11-01T00:00:00Z" }),
  ]);
  assert.deepEqual(
    out.map((i) => i.name),
    ["broken", "new", "aa", "zz", "paused"],
  );
});

test("parseFilter and filterItems", () => {
  assert.equal(parseFilter(null), "all");
  assert.equal(parseFilter("bogus"), "all");
  assert.equal(parseFilter("failing"), "failing");
  const items = [item({ name: "a", error: "x" }), item({ name: "b", ok: "2026-11-01T00:00:00Z" })];
  assert.deepEqual(filterItems(items, "failing").map((i) => i.name), ["a"]);
  assert.equal(filterItems(items, "all").length, 2);
});

test("priorityRange", () => {
  assert.equal(priorityRange("P1", "P1"), "P1");
  assert.equal(priorityRange("P2", "P1"), "P1–P2");
  assert.equal(priorityRange(undefined, "P4"), "P1–P4");
});

test("ruleSummary in a few words", () => {
  assert.equal(ruleSummary(route({ min_priority: "P2", sos_only: true })), "Urgent P1–P2 · SOS only");
  assert.equal(ruleSummary(route({ events: ["urgent", "daily_summary"], environments: ["production"] })), "Urgent P1 · daily summary · production only");
  assert.equal(ruleSummary(route({ events: ["new_issues"], new_min_priority: "P3" })), "New P1–P3");
  assert.equal(ruleSummary(route({ events: ["new_issues"], new_min_priority: "P4" })), "All new issues");
  assert.equal(ruleSummary(route({ events: ["weekly_summary"], project_ids: [1, 2] })), "Weekly summary · 2 projects");
  assert.equal(ruleSummary(route({ events: ["problems", "connected"] })), "2 kinds of update");
  assert.equal(ruleSummary(route({ events: [] })), "Nothing");
  // An older answer without events: the mode's events.
  assert.equal(ruleSummary(route({ events: null, mode: "daily" })), "Daily summary");
});

test("receivesOf: none, off, one and several rules", () => {
  assert.deepEqual(receivesOf(7, []), { text: "Nothing yet: no rule sends to it", rules: [], none: true });
  assert.equal(receivesOf(7, [route({ enabled: false })]).text, "Its rule is turned off");
  assert.equal(receivesOf(7, [route({ channel_id: 8 })]).none, true);
  const one = receivesOf(7, [route({ min_priority: "P2" })]);
  assert.equal(one.text, "Urgent P1–P2");
  assert.equal(one.none, false);
  const two = receivesOf(7, [route({ id: 1, name: "Shop" }), route({ id: 2, name: "Ops", events: ["daily_summary"] })]);
  assert.equal(two.text, "2 rules: Urgent P1, and more");
  assert.deepEqual(two.rules, ["Shop: Urgent P1", "Ops: Daily summary"]);
});

test("scopeOf: organisation, project by name, asset", () => {
  const projects = [{ id: 3, name: "Shop" }];
  assert.deepEqual(scopeOf({ owner_project_id: null, owner_asset_id: null }, projects), { label: "Organisation" });
  assert.deepEqual(scopeOf({ owner_project_id: 3 }, projects), { label: "Project Shop", to: "/projects/3" });
  assert.deepEqual(scopeOf({ owner_project_id: 9 }, projects), { label: "Project #9", to: "/projects/9" });
  assert.deepEqual(scopeOf({ owner_asset_id: 12 }, projects), { label: "Asset #12", to: "/assets/12" });
});

test("sourceCatalogueKey and connectedCounts", () => {
  const src = (kind: string, plugin?: string) => ({ kind, config: plugin ? { plugin } : {} }) as Pick<Integration, "kind" | "config">;
  assert.equal(sourceCatalogueKey(src("git_repository")), "git");
  assert.equal(sourceCatalogueKey(src("container_registry")), "container");
  assert.equal(sourceCatalogueKey(src("plugin", "aws-managed")), "aws");
  assert.equal(sourceCatalogueKey(src("plugin", "kubernetes")), "kubernetes");
  assert.equal(sourceCatalogueKey(src("plugin", "something")), "plugin");
  const n = connectedCounts([{ kind: "slack" }, { kind: "slack" }, { kind: "jira" }], [src("container_image"), src("container_registry")], { linux: 4, windows: 0 });
  assert.deepEqual(n, { slack: 2, jira: 1, container: 2, server: 4 });
});

test("the last delivery uses last_delivery_at when the server sends it, not tests", () => {
  assert.equal(lastDeliveryOf({ ok: "2026-11-06T09:00:00Z" }), "2026-11-06T09:00:00Z");
  assert.equal(lastDeliveryOf({ ok: "2026-11-06T09:00:00Z", delivered: null }), null);
  assert.equal(lastDeliveryOf({ ok: "2026-11-06T09:00:00Z", delivered: "2026-11-01T00:00:00Z" }), "2026-11-01T00:00:00Z");
  // Only tested: no delivery yet, though the test makes it healthy.
  const s = summarise([item({ name: "a", ok: "2026-11-06T09:00:00Z", delivered: null }), item({ name: "b", ok: "2026-11-05T00:00:00Z", delivered: "2026-11-04T00:00:00Z" })]);
  assert.equal(s.lastDelivery, "2026-11-04T00:00:00Z");
  assert.equal(s.lastDeliveryBy, "b");
  assert.equal(s.healthy, 2);
});

test("credentialNote", () => {
  assert.equal(credentialNote("missing")?.tone, "warn");
  assert.equal(credentialNote("server")?.tone, "muted");
  assert.equal(credentialNote("stored"), null);
  assert.equal(credentialNote(""), null);
  assert.equal(credentialNote(undefined), null);
});
