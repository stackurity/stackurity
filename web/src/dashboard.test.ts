import { test } from "node:test";
import assert from "node:assert/strict";
import { assetNoun, glanceTiles, quietKinds, needsYou, reportingCount, reportingRows, slaSplit, sparkPoints, trendText } from "./dashboard.ts";

const now = "2026-10-31T10:00:00Z";
const eod = "2026-11-01T00:00:00Z";

test("Needs you now: empty when nothing needs the user", () => {
  assert.deepEqual(needsYou({ sos: { total: 0, items: [] }, sla: { on_time: 4, due_today: 0, overdue: 0 }, assets: [] }), []);
  assert.deepEqual(needsYou({}), []);
});

test("Needs you now: most urgent first, one action each, deep links", () => {
  const rows = needsYou({
    sos: { total: 1, items: [{ id: 7, kind: "finding", key: "x", title: "OpenSSL RCE on web-1" }] },
    sla: { on_time: 3, due_today: 2, overdue: 5 },
    checkedAt: now,
    endOfToday: eod,
    ignoreRequests: 1,
    fixPlans: 2,
    assets: [
      { id: 3, name: "db-1", kind: "host", collection_status: "stale", last_seen: "2026-10-28T09:00:00Z" },
      { id: 4, name: "shop", kind: "application", collection_status: "partial" },
      { id: 5, name: "web-1", collection_status: "ok" },
    ],
  });
  assert.deepEqual(
    rows.map((r) => r.kind),
    ["sos", "overdue", "due", "reporting", "approval", "approval", "incomplete"],
  );
  assert.equal(rows[0].action.to, "/incidents/7");
  assert.equal(rows[1].title, "5 issues past their fix-by date");
  assert.equal(rows[1].action.to, "/fixes/issues?overdue=true");
  assert.equal(rows[2].action.to, `/fixes/issues?due_after=${encodeURIComponent(now)}&due_before=${encodeURIComponent(eod)}`);
  assert.equal(rows[3].title, "Server db-1: the Stackurity agent hasn't reported since 28 Oct");
  assert.equal(rows[3].action.to, "/assets/3");
  assert.equal(rows[4].action.to, "/approvals");
  assert.equal(rows[5].title, "2 automatic fixes waiting for approval");
  assert.equal(rows[6].action.to, "/assets/4?tab=coverage");
  for (const r of rows) assert.ok(r.action.label && r.action.to.startsWith("/"), r.key);
});

test("several SOS incidents open the filtered list", () => {
  const [r] = needsYou({ sos: { total: 3, items: [] } });
  assert.equal(r.title, "3 open SOS incidents");
  assert.equal(r.action.to, "/incidents?status=open&sos=true");
});

test("stopped reporting: incidents win over stale assets, so grouped incidents need no change", () => {
  const stale = [{ id: 3, name: "db-1", kind: "host", collection_status: "stale", last_seen: "2026-10-28T09:00:00Z" }];
  // Today's per-asset incidents: never "Asset ...", said as the grouped ones are.
  let rows = reportingRows([{ id: 11, kind: "collection", key: "asset:3", title: "Asset db-1 has stopped reporting" }], stale);
  assert.deepEqual(rows.map((r) => r.action.to), ["/incidents/11"]);
  assert.equal(rows[0].title, "Server db-1: the Stackurity agent hasn't reported since 28 Oct");
  // Grouped reporting incidents (stale-reporting branch).
  rows = reportingRows([{ id: 12, kind: "collection", key: "reporting:agent:host:2026-10-30", title: "3 servers: the Stackurity agent hasn't reported since 30 Oct" }], stale);
  assert.equal(rows[0].title, "3 servers: the Stackurity agent hasn't reported since 30 Oct");
  // A failing integration is not about reporting; the stale assets are used.
  rows = reportingRows([{ id: 13, kind: "collection", key: "integration:2", title: "Integration failing" }], stale);
  assert.deepEqual(rows.map((r) => r.action.to), ["/assets/3"]);
});

test("stopped reporting: long lists end with one 'see all' row", () => {
  const stale = Array.from({ length: 7 }, (_, i) => ({ id: i + 1, name: `h${i}`, kind: "repository", collection_status: "stale" }));
  const rows = reportingRows(null, stale);
  assert.equal(rows.length, 5);
  assert.equal(rows[4].title, "Also 3 repositories stopped reporting");
  assert.equal(rows[0].title, "Repository h0 hasn't reported");
  assert.equal(rows[4].action.to, "/assets?status=stale");
});

test("Risk at a glance: every number opens its filtered list", () => {
  const t = glanceTiles({ by_priority: { P1: 2, P3: 9 }, by_kind: { end_of_life: 4 }, known_exploited: 1, regressed: 3 });
  assert.deepEqual(
    t.priority.map((x) => [x.label, x.value, x.to]),
    [
      ["P1 urgent", 2, "/fixes/issues?priority=P1&state=active"],
      ["P2 high", 0, "/fixes/issues?priority=P2&state=active"],
      ["P3 medium", 9, "/fixes/issues?priority=P3&state=active"],
      ["P4 low", 0, "/fixes/issues?priority=P4&state=active"],
    ],
  );
  assert.deepEqual(
    t.flags.map((x) => [x.key, x.value, x.to]),
    [
      ["kev", 1, "/fixes/issues?known_exploited=true"],
      ["eol", 4, "/fixes/issues?kind=end_of_life"],
      ["regressed", 3, "/fixes/issues?state=regressed"],
    ],
  );
});

test("SLA: due today counts as on time; no share without issues", () => {
  assert.deepEqual(slaSplit({ on_time: 6, due_today: 2, overdue: 2 }), { onTime: 8, overdue: 2, dueToday: 2, share: 0.8 });
  assert.equal(slaSplit({ on_time: 0, due_today: 0, overdue: 0 }).share, null);
  assert.equal(slaSplit(null).share, null);
});

test("sparkline: oldest left, higher values higher, flat when constant", () => {
  const p = sparkPoints([0, 10, 5], 100, 20);
  assert.equal(p[0][0], 3);
  assert.equal(p[2][0], 97);
  assert.ok(p[1][1] < p[2][1] && p[2][1] < p[0][1]);
  assert.deepEqual(sparkPoints([4, 4], 100, 20).map((x) => x[1]), [10, 10]);
  assert.deepEqual(sparkPoints([], 100, 20), []);
});

test("trend in words", () => {
  const open = (v: number[]) => ({ checked_at: now, end_of_today: eod, sla: { on_time: 0, due_today: 0, overdue: 0 }, fixed: [], open: v.map((o) => ({ day: now, open: o })) });
  assert.equal(trendText(open([10, 7])), "7 open issues, down 3 in 30 days");
  assert.equal(trendText(open([1, 1])), "1 open issue, no change in 30 days");
  assert.equal(trendText(open([])), "No history yet.");
});

test("assets reporting: removed ones don't count, stale ones aren't reporting", () => {
  assert.deepEqual(reportingCount({ ok: 8, partial: 1, stale: 2, removed: 4 }), { reporting: 9, total: 11, stale: 2 });
  assert.deepEqual(reportingCount(undefined), { reporting: 0, total: 0, stale: 0 });
});

test("asset nouns follow the reporting incidents", () => {
  assert.equal(assetNoun("host"), "server");
  assert.equal(assetNoun("repository", 2), "repositories");
  assert.equal(assetNoun("managed_service"), "managed service");
  assert.equal(assetNoun(undefined), "asset");
});

test("what stopped reporting is named by kind, never 'asset'", () => {
  const a = [
    { id: 1, name: "web", kind: "host", collection_status: "stale" },
    { id: 2, name: "shop", kind: "repository", collection_status: "stale" },
    { id: 3, name: "blog", kind: "repository", collection_status: "stale" },
    { id: 4, name: "api", kind: "host", collection_status: "ok" },
  ];
  assert.equal(quietKinds(a, 3), "2 repositories and 1 server stopped reporting");
  assert.equal(quietKinds(a.slice(1, 2), 1), "1 repository stopped reporting");
  // The assets at hand don't account for every stale one: no nouns guessed.
  assert.equal(quietKinds(a, 5), "5 not reporting");
});
