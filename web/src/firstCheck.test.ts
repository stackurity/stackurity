import { test } from "node:test";
import assert from "node:assert/strict";
import { SETUP_STEPS, countFixes, firstCheckNumbers, firstCheckPhase, milestoneText, milestoneTiles, phaseText, progressRows } from "./firstCheck.ts";
import type { AssetCoverageRow, FirstResult, FixGroup, FixPlace } from "./api.ts";

const result = (p: Partial<FirstResult> = {}): FirstResult => ({
  id: 7,
  name: "web-1",
  kind: "host",
  environment: "production",
  created_at: "2026-11-03T10:00:00Z",
  last_seen: "2026-11-03T10:01:00Z",
  checked: false,
  packages: 0,
  issues: 0,
  fixes_now: 0,
  ...p,
});

const cov = (p: Partial<AssetCoverageRow> = {}): AssetCoverageRow =>
  ({
    id: 7,
    name: "web-1",
    kind: "host",
    collection_status: "ok",
    group: "healthy",
    state: "",
    components: 0,
    checked: 0,
    not_checked: { user: 0, stackurity: 0, automatic: 0, none: 0 },
    problem_scopes: 0,
    last_report: null,
    ...p,
  }) as AssetCoverageRow;

test("the steps say what happens, each with a sentence", () => {
  assert.deepEqual(
    SETUP_STEPS.map((s) => s.label),
    ["Create a project", "Add a server or repo", "First check", "Review fixes", "Choose alerts", "Invite your team"],
  );
  assert.deepEqual(
    SETUP_STEPS.map((s) => s.key),
    ["project", "asset", "waiting", "result", "notify", "invite"],
  );
  for (const s of SETUP_STEPS) assert.ok(s.text.length > 0 && s.text.endsWith("."), s.key);
});

test("nothing reported yet: waiting, no numbers shown", () => {
  const x = firstCheckNumbers([], null, null);
  assert.equal(firstCheckPhase(x), "waiting");
  const rows = progressRows(x, "waiting", "server");
  assert.deepEqual(
    rows.map((r) => [r.label, r.value, r.state]),
    [
      ["Agent connected", "", "active"],
      ["Components found", "", "pending"],
      ["Issues found", "", "pending"],
      ["Fixes recommended", "", "pending"],
    ],
  );
  assert.equal(phaseText("waiting", x, "server", "your server").title, "Waiting for your server to report");
  assert.match(phaseText("waiting", x, "repo", "your repository").text, /next CI run/);
  // What reported is named for the source.
  assert.equal(progressRows(x, "waiting", "repo")[0].label, "CI report received");
  assert.equal(progressRows(x, "waiting", "sbom")[0].label, "SBOM received");
  // Opened on a later step: what was sent is not known.
  assert.equal(progressRows(x, "waiting", undefined)[0].label, "Report received");
});

test("reported, first check running: the numbers so far, issues not final", () => {
  const x = firstCheckNumbers([result({ packages: 1676, issues: 12 })], [cov({ components: 1676, checked: 900 })], null);
  assert.equal(firstCheckPhase(x), "checking");
  assert.deepEqual(
    progressRows(x, "checking", "server").map((r) => [r.key, r.value, r.state]),
    [
      ["reported", "1 asset", "done"],
      ["components", "1,676", "done"],
      ["issues", "12", "active"],
      ["fixes", "", "pending"],
    ],
  );
  assert.equal(phaseText("checking", x, "server", "").title, "Checking what it found");
});

test("checked, vulnerability data not synced: says how many wait and that it resolves", () => {
  const x = firstCheckNumbers(
    [result({ checked: true, packages: 300, issues: 2 })],
    [cov({ components: 300, checked: 40, not_checked: { user: 0, stackurity: 0, automatic: 260, none: 0 } })],
    1,
  );
  assert.equal(x.componentsWaiting, 260);
  assert.equal(firstCheckPhase(x), "feeds");
  const rows = progressRows(x, "feeds", "server");
  assert.deepEqual(rows.map((r) => r.state), ["done", "done", "active", "active"]);
  assert.equal(rows[3].value, "1");
  const t = phaseText("feeds", x, "server", "");
  assert.equal(t.title, "Waiting for vulnerability data");
  assert.match(t.text, /^260 components wait for vulnerability data, which is still being downloaded/);
  assert.match(t.text, /checked as soon as it has synced/);
  // Overdue (feeds off, air-gapped): it will not resolve on its own.
  const o = phaseText("feeds", x, "server", "", true);
  assert.equal(o.title, "Vulnerability data is missing");
  assert.match(o.text, /Intelligence/);
});

test("done: the milestone from the real numbers", () => {
  const x = firstCheckNumbers(
    [result({ checked: true, packages: 1676, issues: 412 })],
    [cov({ components: 1676, checked: 1593, not_checked: { user: 3, stackurity: 60, automatic: 0, none: 20 } })],
    23,
  );
  assert.equal(firstCheckPhase(x), "done");
  assert.deepEqual(progressRows(x, "done", "server").map((r) => r.state), ["done", "done", "done", "done"]);
  assert.deepEqual(
    milestoneTiles(x).map((t) => [t.label, t.value]),
    [
      ["Asset", "1"],
      ["Components", "1,676"],
      ["Issues", "412"],
      ["Coverage", "95%"],
    ],
  );
  assert.equal(
    milestoneText(x),
    "95% of the components were checked against current vulnerability data. The 412 issues are grouped into 23 fixes, most urgent first.",
  );
});

test("done with nothing found, and with nothing to check", () => {
  const clean = firstCheckNumbers([result({ checked: true, packages: 10 })], [cov({ components: 10, checked: 10 })], 0);
  assert.equal(firstCheckPhase(clean), "done");
  assert.equal(milestoneText(clean), "100% of the components were checked against current vulnerability data. No known vulnerabilities or end-of-life software.");
  const empty = firstCheckNumbers([result({ checked: true })], [cov()], 0);
  assert.equal(firstCheckPhase(empty), "done");
  assert.equal(milestoneTiles(empty)[3].value, "None");
  assert.equal(milestoneText(empty), "No components were found.");
});

test("coverage counts only the assets that reported, and only once every one has a row", () => {
  const results = [result({ id: 1, checked: true, packages: 10 }), result({ id: 2, checked: true, packages: 30 })];
  const rows = [cov({ id: 1, components: 10, checked: 10 }), cov({ id: 2, components: 30, checked: 20 }), cov({ id: 99, components: 1000, checked: 0 })];
  const x = firstCheckNumbers(results, rows, 3);
  assert.equal(x.coverage, 75);
  assert.equal(x.assets, 2);
  assert.equal(x.components, 40);
  // A row missing (removed meanwhile): coverage unknown, never a made-up share.
  const partial = firstCheckNumbers(results, rows.slice(0, 1), 3);
  assert.equal(partial.coverage, null);
  assert.equal(firstCheckPhase(partial), "done");
  assert.equal(milestoneTiles(partial)[3].value, "–");
});

const place = (asset_id: number): FixPlace => ({ group_id: `${asset_id}:x`, asset_id, asset_name: `a${asset_id}`, asset_kind: "host", environment: "", finding_count: 1 });

test("fixes recommended: the same fix on two new assets counts once", () => {
  // Grouped by fix: one entry with a place on each asset.
  const merged = [{ id: "1:pkg:lodash", asset_id: 1, fix_key: "pkg:npm/lodash@4.17.21", places: [place(1), place(2)] }] as FixGroup[];
  assert.equal(countFixes(merged, [1, 2]), 1);
  // Grouped by asset: two entries with the same fix_key.
  const split = [
    { id: "1:pkg:lodash", asset_id: 1, fix_key: "pkg:npm/lodash@4.17.21", places: null },
    { id: "2:pkg:lodash", asset_id: 2, fix_key: "pkg:npm/lodash@4.17.21", places: null },
  ] as FixGroup[];
  assert.equal(countFixes(split, [1, 2]), 1);
  // Fixes only on older assets of the project are not counted; distinct fixes are.
  const mixed = [
    ...merged,
    { id: "2:security_updates", asset_id: 2, fix_key: "", places: null },
    { id: "99:security_updates", asset_id: 99, fix_key: "", places: null },
    { id: "3:pkg:axios", asset_id: 3, fix_key: "pkg:npm/axios@1.0.0", places: [place(3), place(99)] },
  ] as FixGroup[];
  assert.equal(countFixes(mixed, [1, 2]), 2);
  assert.equal(countFixes(mixed, [1, 2, 3]), 3);
  assert.equal(countFixes([], [1]), 0);
});
