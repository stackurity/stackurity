import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CARD_ASSETS,
  SEGMENTS,
  aclCommand,
  actionCards,
  assetPercent,
  ecosystemLink,
  headline,
  notCheckedParts,
  percent,
  reportingLine,
  reportingText,
  secondCheckNumbers,
  segmentLink,
} from "./coverage.ts";
import type { AssetCoverageRow, CoverageOverview, CoverageRow, InventoryRow, Unchecked } from "./api.ts";

const ov: CoverageOverview = {
  total: 100,
  segments: { checked: 93, needs_you: 2, not_supported: 3, waiting: 1, no_advisories: 1 },
  ecosystems: [],
};

test("the headline: share checked, every segment in bar order, segments add up to the total", () => {
  const h = headline(ov);
  assert.equal(h.text, "93% of your components were checked");
  assert.equal(h.pct, 93);
  assert.deepEqual(
    h.segments.map((s) => s.key),
    ["checked", "needs_you", "not_supported", "waiting", "no_advisories"],
  );
  assert.equal(
    h.segments.reduce((a, s) => a + s.count, 0),
    h.total,
  );
  assert.equal(Math.round(h.segments.reduce((a, s) => a + s.share, 0)), 100);
  assert.deepEqual(
    h.segments.map((s) => s.label),
    ["Checked", "Needs you", "Not supported yet", "Waiting for data", "No published advisories"],
  );
});

test("every segment and legend item links to the component list filtered to that segment", () => {
  for (const s of headline(ov).segments) {
    assert.equal(s.to, `/components?segment=${s.key}`);
    assert.equal(s.to, segmentLink(s.key));
  }
  assert.equal(SEGMENTS.length, 5);
});

test("the share rounds down: 100% only when every component was checked", () => {
  assert.equal(percent(999, 1000), 99);
  assert.equal(percent(1000, 1000), 100);
  assert.equal(percent(0, 0), 0);
  assert.equal(headline({ ...ov, total: 1000, segments: { ...ov.segments, checked: 999 } }).pct, 99);
});

test("empty headline: no components yet, no percent", () => {
  const h = headline({ total: 0, segments: { checked: 0, needs_you: 0, not_supported: 0, waiting: 0, no_advisories: 0 }, ecosystems: [] });
  assert.equal(h.pct, null);
  assert.equal(h.text, "No components reported yet");
  assert.ok(h.segments.every((s) => s.count === 0));
  assert.equal(headline(null).pct, null);
});

test("assets reporting: removed assets are not counted", () => {
  assert.deepEqual(reportingLine({ ok: 4, partial: 1, stale: 1, removed: 3 }), {
    reporting: 5,
    total: 6,
    stale: 1,
    text: "5 of 6 assets reporting",
  });
  assert.equal(reportingLine({}).text, "0 of 0 assets reporting");
});

const row = (p: Partial<InventoryRow>): InventoryRow => ({ asset_id: 1, asset_name: "web", name: "x", ...p }) as InventoryRow;

const u: Unchecked = {
  need_you: 5,
  need_you_components: 4,
  need_you_applications: 1,
  not_supported: 3,
  waiting: 1,
  no_advisories: 0,
  overdue: false,
  groups: [
    {
      reason: "unreadable_version",
      actor: "user",
      components: 3,
      assets: 2,
      items: [
        { key: "no_version", label: "no version recorded", fix: "Each component's row says what to do…", docs: "https://docs/repos", components: 2, assets: 2 },
        { key: "windows_no_ubr", label: "Windows update revision (UBR) not reported", fix: "Update the agent", components: 1, assets: 1 },
      ],
    },
    { reason: "other", actor: "user", components: 1, assets: 1, items: [{ key: "npm", label: "npm components", components: 1, assets: 1 }] },
    { reason: "unreadable_files", actor: "user", components: 0, assets: 1, items: [{ key: "permission_denied", label: "files", docs: "https://docs/acl", components: 0, assets: 1 }] },
    { reason: "unsupported", actor: "stackurity", components: 3, assets: 1, items: [] },
    { reason: "waiting_for_data", actor: "automatic", components: 1, assets: 1, items: [] },
  ],
};

test("fix cards: only what needs you, plain titles, assets as chips, most components first", () => {
  const rows = [
    row({ asset_id: 1, asset_name: "web", name: "left-pad", unchecked_reason: "unreadable_version", unchecked_cause: "no_version", unchecked_fix: "Commit package-lock.json next to web/package.json so exact versions can be read, then check again." }),
    row({ asset_id: 2, asset_name: "api", name: "chalk", unchecked_reason: "unreadable_version", unchecked_cause: "no_version", unchecked_fix: "Commit package-lock.json next to web/package.json so exact versions can be read, then check again." }),
    row({ asset_id: 3, asset_name: "win1", name: "Windows", unchecked_reason: "unreadable_version", unchecked_cause: "windows_no_ubr" }),
    row({ asset_id: 1, asset_name: "web", name: "odd", unchecked_reason: "other" }),
  ];
  const scopes = [
    { asset_id: 9, asset_name: "shop", scope: "app-permissions:/var/www/shop", status: "unsupported" },
    { asset_id: 9, asset_name: "shop", scope: "dpkg", status: "failed" },
  ] as CoverageRow[];
  const cards = actionCards(u, rows, scopes);
  assert.deepEqual(
    cards.map((c) => c.key),
    ["version:no_version", "version:windows_no_ubr", "other", "files"],
  );
  const [nov, win, other, files] = cards;
  assert.equal(nov.title, "2 components have no readable version");
  // One fix shared by every row says more than the summary's.
  assert.equal(nov.fix, "Commit package-lock.json next to web/package.json so exact versions can be read, then check again.");
  assert.deepEqual(
    nov.assets.map((a) => a.name),
    ["api", "web"],
  );
  assert.equal(nov.assets[1].to, "/assets/1?tab=inventory&unchecked=unreadable_version");
  assert.equal(nov.docs, "https://docs/repos");
  assert.equal(nov.command, undefined);
  assert.equal(win.title, "Windows update level not reported");
  assert.equal(win.fix, "Update the Stackurity agent on the host, then check again.");
  assert.equal(other.title, "1 component could not be checked");
  assert.equal(files.title, "1 application has files the agent can't read");
  assert.deepEqual(
    files.assets.map((a) => a.name),
    ["shop"],
  );
  // A command to copy, so the card's one button is "Copy command".
  assert.equal(files.command, "sudo setfacl -R -m u:stackurity:rX /var/www/shop && sudo setfacl -R -d -m u:stackurity:rX /var/www/shop");
  for (const c of cards) assert.ok(c.fix.length <= 110, `one line: ${c.fix}`);
});

test("fix cards: none when nothing needs you", () => {
  assert.deepEqual(actionCards({ ...u, need_you: 0, groups: u.groups.filter((g) => g.actor !== "user") }, [], []), []);
  assert.deepEqual(actionCards(null, [], []), []);
});

test("fix cards: chips stop at a few assets and count the rest", () => {
  const rows = Array.from({ length: 7 }, (_, i) =>
    row({ asset_id: i + 1, asset_name: `a${i + 1}`, unchecked_reason: "unreadable_version", unchecked_cause: "no_version", unchecked_fix: `fix ${i}` }),
  );
  const [c] = actionCards({ ...u, groups: [u.groups[0]] }, rows, []);
  assert.equal(c.assets.length, CARD_ASSETS);
  assert.equal(c.moreAssets, 7 - CARD_ASSETS);
  // Different fixes per row: the short one for the cause.
  assert.equal(c.fix, "Commit the lockfile, or include versions in the SBOM, then check again.");
});

test("the ACL command quotes paths that need it", () => {
  assert.equal(aclCommand(["/srv/my site"]), "sudo setfacl -R -m u:stackurity:rX '/srv/my site' && sudo setfacl -R -d -m u:stackurity:rX '/srv/my site'");
});

test("ecosystem chips link to their components when they are a package type", () => {
  const e = { key: "npm", label: "npm", type: "npm", components: 3, checked: 3, not_supported: 0, status: "checked" as const, requested: false };
  assert.equal(ecosystemLink(e), "/components?type=npm");
  assert.equal(ecosystemLink({ ...e, key: "deb:ubuntu-24.04", type: "deb" }), null);
  assert.equal(ecosystemLink({ ...e, key: "windows", type: "generic" }), null);
});

const asset = (p: Partial<AssetCoverageRow>): AssetCoverageRow => ({
  id: 1,
  name: "web",
  kind: "repository",
  collection_status: "ok",
  reporting: { source: "agent", override: "auto", mode: "agent", runs: 6, usual_seconds: 86400, due_after_seconds: 172800 },
  group: "healthy",
  state: "healthy",
  components: 10,
  checked: 9,
  not_checked: { user: 1, stackurity: 0, automatic: 0, none: 0 },
  problem_scopes: 0,
  last_report: "2026-10-30T10:00:00Z",
  ...p,
});

test("asset rows: calm reporting words", () => {
  const now = new Date("2026-10-31T12:00:00Z");
  assert.deepEqual(reportingText(asset({}), now), { text: "Reporting daily", tone: "good" });
  assert.deepEqual(reportingText(asset({ collection_status: "stale", last_report: "2026-10-26T08:00:00Z" }), now), { text: "Quiet since 26 Oct", tone: "warn" });
  assert.equal(
    reportingText(asset({ reporting: { source: "scan", override: "auto", mode: "one_off", runs: 1, usual_seconds: null, due_after_seconds: null, as_of: "2026-10-12T00:00:00Z" } }), now).text,
    "Scanned once (12 Oct)",
  );
  assert.equal(reportingText(asset({ last_report: null, reporting: { source: "", override: "auto", mode: "unknown", runs: 0, usual_seconds: null, due_after_seconds: null } }), now).text, "No report yet");
  assert.equal(reportingText(asset({ collection_status: "partial" }), now).text, "Reporting; last report incomplete");
});

test("asset rows: share checked and not-checked counts by who acts", () => {
  assert.equal(assetPercent(asset({})), 90);
  assert.equal(assetPercent(asset({ components: 0, checked: 0 })), null);
  assert.deepEqual(
    notCheckedParts(asset({ not_checked: { user: 2, stackurity: 3, automatic: 1, none: 0 } })).map((p) => p.text),
    ["2 need you", "3 not supported", "1 waiting"],
  );
  assert.deepEqual(notCheckedParts(asset({ not_checked: { user: 0, stackurity: 0, automatic: 0, none: 0 } })), []);
});

test("second check: four numbers, a warning only for disagreements, an empty state", () => {
  const s = secondCheckNumbers({ agreed: 40, disagreed: 2, could_not_check: 3, pending: 5, logged_30d: 2, recent: [] });
  assert.deepEqual(
    s.items.map((i) => `${i.label} ${i.value}`),
    ["Agreed 40", "Disagreed 2", "Couldn't check 3", "Waiting 5"],
  );
  assert.equal(s.disagreed, 2);
  assert.equal(s.empty, false);
  assert.equal(secondCheckNumbers(null).empty, true);
  assert.equal(secondCheckNumbers({ agreed: 1, disagreed: 0, could_not_check: 0, pending: 0, logged_30d: 0, recent: [] }).disagreed, 0);
});
