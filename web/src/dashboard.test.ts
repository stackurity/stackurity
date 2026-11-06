import { test } from "node:test";
import assert from "node:assert/strict";
import {
  assetNoun,
  feedFreshness,
  glanceTiles,
  hiddenReasons,
  quietKinds,
  needsYou,
  reportingCount,
  reportingRows,
  slaSplit,
  sparkPoints,
  termParts,
  trendText,
  type FeedLike,
  type Term,
} from "./dashboard.ts";

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
  assert.equal(rows[4].title, "Also 3 repositories not reporting");
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

test("SLA: due today counts as within deadline; no share without issues", () => {
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
  assert.equal(quietKinds(a, 3), "2 repositories and 1 server not reporting");
  assert.equal(quietKinds(a.slice(1, 2), 1), "1 repository not reporting");
  // The assets at hand don't account for every stale one: no nouns guessed.
  assert.equal(quietKinds(a, 5), "5 not reporting");
});

test("Needs you now: each action says what it opens", () => {
  const rows = needsYou({
    sos: { total: 31, items: [{ id: 1, kind: "finding", key: "x", title: "a" }] },
    sla: { on_time: 0, due_today: 1, overdue: 2 },
    checkedAt: now,
    endOfToday: eod,
    ignoreRequests: 1,
    fixPlans: 1,
    assets: [{ id: 3, name: "db-1", kind: "host", collection_status: "stale" }],
  });
  assert.deepEqual(
    rows.map((r) => [r.title, r.action.label]),
    [
      ["31 open SOS incidents", "Open the SOS incident list"],
      ["2 issues past their fix-by date", "Open the overdue issues"],
      ["1 issue due by the end of today", "Open the issues due today"],
      ["Server db-1: the Stackurity agent hasn't reported", "Open the asset"],
      ["1 request to ignore issues is waiting for a decision", "Open approvals"],
      ["1 automatic fix waiting for approval", "Open automatic fixes"],
    ],
  );
  const one = needsYou({ sos: { total: 1, items: [{ id: 9, kind: "finding", key: "x", title: "OpenSSL RCE" }] } });
  assert.deepEqual([one[0].detail, one[0].action.label], ["Open SOS incident", "Open the incident"]);
});

test("terms: the first use of each word in a block gets its meaning, once", () => {
  const seen = new Set<Term>();
  assert.deepEqual(termParts("31 open SOS incidents", seen), ["31 open ", { text: "SOS", term: "sos" }, " ", { text: "incidents", term: "incident" }]);
  assert.deepEqual(termParts("2 issues past their fix-by date", seen), ["2 ", { text: "issues", term: "issue" }, " past their ", { text: "fix", term: "fix" }, "-by date"]);
  // Already explained in this block: plain text.
  assert.deepEqual(termParts("More SOS incidents and issues", seen), ["More SOS incidents and issues"]);
  assert.deepEqual(termParts("", new Set()), []);
  // "prefix" is not the word fix.
  assert.deepEqual(termParts("a prefix", new Set()), ["a prefix"]);
});

test("not shown in Top fixes: no fix published is never said as a price", () => {
  const r = hiddenReasons({ no_fix: { findings: 7 }, lower_priority: { findings: 49 }, old_kernels: { findings: 0 } }, 2, 0);
  assert.deepEqual(
    r.map((x) => [x.key, x.n, x.to]),
    [
      ["no_fix", 7, "/fixes?bucket=no_fix"],
      ["lower_priority", 49, "/fixes?bucket=lower_priority"],
      ["suppressed", 2, "/fixes/issues?state=suppressed"],
    ],
  );
  for (const x of r) assert.doesNotMatch(x.text, /free|paid|pay/i, x.key);
  assert.equal(r[0].text, "have no fix in the standard updates yet");
  assert.match(r[0].title ?? "", /Ubuntu Pro/);
  assert.equal(r[1].text, "are lower priority (P2 to P4, no SOS rule)");
  assert.deepEqual(hiddenReasons(null), []);
});

const feed = (name: string, over: Partial<FeedLike> = {}): FeedLike => ({
  name,
  kind: "vulnerability",
  enabled: true,
  last_attempt: "2026-11-03T09:00:00Z",
  last_success: "2026-11-03T09:00:00Z",
  last_error: "",
  stale: false,
  ...over,
});

test("feed freshness: fresh, the newest success across enabled feeds", () => {
  const f = feedFreshness([
    feed("osv", { last_success: "2026-11-03T08:00:00Z" }),
    feed("kev:cisa", { last_success: "2026-11-03T09:30:00Z" }),
    feed("old", { enabled: false, last_success: "2026-11-03T10:00:00Z" }),
  ]);
  assert.equal(f.state, "fresh");
  assert.equal(f.lastSuccess, "2026-11-03T09:30:00Z");
  assert.equal(f.warning, "");
});

test("feed freshness: stale when the server says a synced feed is past its limit", () => {
  const f = feedFreshness([feed("osv"), feed("kev:cisa", { stale: true, last_success: "2026-11-02T09:00:00Z", last_error: "timeout" })]);
  assert.equal(f.state, "stale");
  assert.deepEqual(f.stale, ["kev:cisa"]);
  assert.deepEqual(f.failing, []);
  assert.equal(f.lastSuccess, "2026-11-03T09:00:00Z");
  assert.match(f.warning, /^Data source kev:cisa is out of date: no successful sync within its freshness limit/);
  const two = feedFreshness([feed("a", { stale: true }), feed("b", { stale: true }), feed("c", { stale: true })]);
  assert.match(two.warning, /^Data sources a, b and c are out of date: .* their freshness limit/);
  // A disabled feed is never stale.
  assert.equal(feedFreshness([feed("osv"), feed("x", { enabled: false, stale: true })]).state, "fresh");
});

test("feed freshness: failing while the data is still within its limit", () => {
  const f = feedFreshness([feed("osv", { last_error: "HTTP 503" }), feed("kev:cisa")]);
  assert.equal(f.state, "failing");
  assert.deepEqual(f.failing, ["osv"]);
  assert.equal(f.warning, "Data source osv is failing to sync. The data is still within its freshness limit.");
  // Stale wins over failing when both happen.
  assert.equal(feedFreshness([feed("osv", { last_error: "x" }), feed("kev", { stale: true })]).state, "stale");
});

test("feed freshness: never synced, waiting for the first sync, or turned off", () => {
  const never = feedFreshness([feed("osv", { last_success: null, stale: true, last_error: "dial tcp: timeout" })]);
  assert.equal(never.state, "never");
  assert.equal(never.lastSuccess, null);
  assert.match(never.warning, /never been downloaded/);
  const pending = feedFreshness([feed("osv", { last_success: null, last_attempt: null, stale: true })]);
  assert.equal(pending.state, "pending");
  assert.match(pending.warning, /first sync/);
  // A new feed waiting for its first sync next to a synced one is not a warning.
  assert.equal(feedFreshness([feed("osv"), feed("new", { last_success: null, last_attempt: null, stale: true })]).state, "fresh");
  assert.equal(feedFreshness([feed("osv", { enabled: false })]).state, "never");
  assert.match(feedFreshness([]).warning, /turned off/);
});
