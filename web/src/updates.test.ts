import { test } from "node:test";
import assert from "node:assert/strict";
import { countsText, installsQuery, packageName, updateFilterOf, versionsText } from "./updates.ts";

test("the filter comes from the URL, any by default", () => {
  assert.equal(updateFilterOf("major"), "major");
  assert.equal(updateFilterOf("patch"), "patch");
  assert.equal(updateFilterOf(null), "any");
  assert.equal(updateFilterOf(""), "any");
  // Not a value the API takes: never sent.
  assert.equal(updateFilterOf("all"), "any");
});

test("the installs query names the filter, and the asset only when one is picked", () => {
  assert.deepEqual(installsQuery("any", "", 50, 0), { update_type: "any", limit: 50, offset: 0 });
  assert.deepEqual(installsQuery("minor", "12", 50, 100), { update_type: "minor", limit: 50, offset: 100, asset_id: "12" });
});

test("counts read largest change first and skip zeros", () => {
  assert.equal(countsText({ patch: 41, minor: 12, major: 3, total: 56 }), "56 installs behind: 3 major, 12 minor, 41 patch");
  assert.equal(countsText({ patch: 1, minor: 0, major: 0, total: 1 }), "1 install behind: 1 patch");
  assert.equal(countsText({ patch: 0, minor: 0, major: 0, total: 0 }), "Every registry package is on its latest stable release.");
  assert.equal(countsText(undefined), "Every registry package is on its latest stable release.");
});

test("package names as each ecosystem writes them", () => {
  assert.equal(packageName({ type: "npm", namespace: "", name: "bootstrap" }), "bootstrap");
  assert.equal(packageName({ type: "npm", namespace: "@babel", name: "core" }), "@babel/core");
  assert.equal(packageName({ type: "composer", namespace: "symfony", name: "console" }), "symfony/console");
  assert.equal(packageName({ type: "maven", namespace: "org.slf4j", name: "slf4j-api" }), "org.slf4j:slf4j-api");
});

test("installed versions are capped", () => {
  assert.equal(versionsText(["4.17.15", "4.17.20"]), "4.17.15, 4.17.20");
  assert.equal(versionsText(["7.1.0", "7.2.0", "7.3.0", "7.4.0", "7.5.0"]), "7.1.0, 7.2.0, 7.3.0 +2 more");
  assert.equal(versionsText(null), "");
});
