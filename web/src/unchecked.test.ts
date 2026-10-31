import { test } from "node:test";
import assert from "node:assert/strict";
import { groupByFix, needYouText, uncheckedBanner, uncheckedSummaryLine, unsupportedSentence, waitingSentence } from "./unchecked.ts";

const empty = { need_you: 0, not_supported: 0, waiting: 0, no_advisories: 0, overdue: false, groups: [] };

test("no banner when everything was checked", () => {
  assert.equal(uncheckedBanner(empty), null);
  assert.equal(uncheckedBanner(null), null);
  assert.equal(uncheckedSummaryLine(empty), "Every component was checked.");
});

test("releases with no published advisories never raise the banner, and are still said", () => {
  assert.equal(uncheckedBanner({ ...empty, no_advisories: 4 }), null);
  assert.equal(uncheckedSummaryLine({ ...empty, no_advisories: 4 }), "Every component was checked; 4 releases have no published advisories.");
});

test("need you says components and applications apart", () => {
  assert.equal(needYouText({ ...empty, need_you: 3, need_you_components: 2, need_you_applications: 1 }), "2 components and 1 application need you");
  assert.equal(needYouText({ ...empty, need_you: 1, need_you_components: 1, need_you_applications: 0 }), "1 component needs you");
  assert.equal(needYouText({ ...empty, need_you: 2, need_you_components: 0, need_you_applications: 2 }), "2 applications need you");
});

test("components are grouped by what to do, each named once", () => {
  const fix = "Commit package-lock.json next to web/package.json";
  const g = groupByFix([
    { name: "chalk", asset_id: 1, unchecked_fix: fix },
    { name: "left-pad", asset_id: 1, unchecked_fix: fix },
    { name: "left-pad", asset_id: 2, unchecked_fix: fix },
    { name: "Chrome", asset_id: 3, unchecked_fix: "Repair the program" },
  ]);
  assert.equal(g.length, 2);
  assert.deepEqual(
    g[0].components.map((c) => [c.name, c.assets]),
    [
      ["chalk", 1],
      ["left-pad", 2],
    ],
  );
});

test("the owner's example: leads with what needs the user, warning tone", () => {
  const b = uncheckedBanner({ ...empty, need_you: 2, need_you_components: 2, need_you_applications: 0, not_supported: 5, waiting: 1, no_advisories: 3 })!;
  assert.equal(b.tone, "warn");
  assert.deepEqual(
    b.parts.map((p) => p.text),
    ["2 components need you", "5 Stackurity doesn't support yet", "1 resolves on its own"],
  );
  assert.equal(b.noAdvisories, 3);
});

test("informational when nothing needs the user", () => {
  const b = uncheckedBanner({ ...empty, not_supported: 5, waiting: 2 })!;
  assert.equal(b.tone, "info");
  assert.deepEqual(
    b.parts.map((p) => p.key),
    ["not_supported", "waiting"],
  );
  assert.equal(b.parts[1].text, "2 resolve on their own");
});

test("out-of-date data is a warning, and no longer 'resolves on its own'", () => {
  const b = uncheckedBanner({ ...empty, waiting: 3, overdue: true })!;
  assert.equal(b.tone, "warn");
  assert.equal(b.parts[0].text, "3 waiting on out-of-date data");
  assert.match(waitingSentence({ key: "osv:PyPI", label: "PyPI", components: 3, assets: 1, overdue: true }), /out of date/);
  assert.equal(
    waitingSentence({ key: "osv:npm", label: "npm", components: 3, assets: 1 }),
    "Waiting for vulnerability data for npm; this resolves on its own.",
  );
});

test("unsupported sentences are neutral and plain", () => {
  assert.equal(
    unsupportedSentence({ key: "cocoapods|ecosystem", label: "CocoaPods packages", components: 5, assets: 2 }),
    "5 components use CocoaPods packages, which Stackurity doesn't check yet.",
  );
  assert.equal(
    unsupportedSentence({ key: "cms", label: "WordPress core", components: 1, assets: 1 }),
    "1 component uses WordPress core, which Stackurity doesn't check yet.",
  );
});

test("no internal words in what people read", () => {
  const b = uncheckedBanner({ ...empty, need_you: 1, not_supported: 1, waiting: 1, overdue: true })!;
  const words = [...b.parts.map((p) => p.text), waitingSentence({ key: "osv:npm", label: "npm", components: 1, assets: 1 })].join(" ");
  assert.doesNotMatch(words, /feed|evaluation gap|intelligence/i);
});
