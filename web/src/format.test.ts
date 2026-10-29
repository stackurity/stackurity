import { test } from "node:test";
import assert from "node:assert/strict";
import { assetDistinctions, assetLabel, groupAssetsByKind } from "./format.ts";

// The owner's case (Fixes, Asset filter): a server and a repository both
// called commmerceblog, and two Ghost directories on it with one name.
const assets = [
  { id: 3, name: "commmerceblog", kind: "host", environment: "production" },
  { id: 7, name: "commmerceblog", kind: "repository", environment: "" },
  { id: 4, name: "ghost on commmerceblog", kind: "application", environment: "production", attributes: { app_dir: "/var/www/ghost/versions/6.22.0" }, collection_status: "removed" },
  { id: 5, name: "ghost on commmerceblog", kind: "application", environment: "production", attributes: { app_dir: "/var/www/ghost/versions/6.52.0" } },
  { id: 9, name: "analytics", kind: "repository", environment: "" },
  { id: 10, name: "web", kind: "host", environment: "staging" },
  { id: 11, name: "web", kind: "host", environment: "production" },
  { id: 12, name: "db", kind: "host", environment: "" },
  { id: 13, name: "db", kind: "host", environment: "" },
];

test("names that collide get what tells them apart", () => {
  const d = assetDistinctions(assets);
  const label = (id: number) => assetLabel(assets.find((a) => a.id === id)!, d);
  assert.equal(label(3), "commmerceblog (server)");
  assert.equal(label(7), "commmerceblog (repository)");
  assert.equal(label(4), "ghost on commmerceblog (/var/www/ghost/versions/6.22.0, removed)");
  assert.equal(label(5), "ghost on commmerceblog (/var/www/ghost/versions/6.52.0)");
  assert.equal(label(9), "analytics");
  assert.equal(label(10), "web (staging)");
  assert.equal(label(12), "db (#12)");
});

test("grouped by kind, servers first", () => {
  const g = groupAssetsByKind(assets);
  assert.deepEqual(
    g.map((x) => x.label),
    ["Servers", "Applications", "Repositories"],
  );
  assert.deepEqual(
    g[2].items.map((a) => a.id),
    [9, 7],
  );
});
