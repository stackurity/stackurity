import { test } from "node:test";
import assert from "node:assert/strict";
import type { SearchComponent, SearchResults, SearchSummary } from "./api.ts";
import { searchOverview, searchSuggestions } from "./searchOverview.ts";

const component = (id: number): SearchComponent => ({
  id,
  purl_key: `pkg:deb/ubuntu/c${id}`,
  type: "deb",
  namespace: "ubuntu",
  name: `c${id}`,
  rank: 0,
  asset_count: 3,
  versions: ["1.0"],
  open_findings: 0,
  assets: [],
  version_assets: 0,
});

function results(summary: Partial<SearchSummary> | undefined, components = [component(1)]): SearchResults {
  return {
    query: "openssl",
    vulnerabilities: [],
    findings: [],
    assets: [],
    components,
    teams: [],
    members: [],
    more: {},
    summary: summary && {
      components: 0,
      versions: 0,
      installed_assets: 0,
      component_query: "openssl",
      findings_query: "openssl",
      open_findings: 0,
      affected_assets: 0,
      critical: 0,
      urgent: 0,
      ...summary,
    },
  };
}

test("the overview uses the server's counts, not the capped lists, and links each figure to its list", () => {
  // 50 components returned (the cap), 64 matching: the figure says 64.
  const many = Array.from({ length: 50 }, (_, i) => component(i + 1));
  const f = searchOverview(
    results({ components: 64, versions: 120, installed_assets: 1830, open_findings: 2400, affected_assets: 900, critical: 12, urgent: 3 }, many),
  );
  const by = Object.fromEntries(f.map((x) => [x.key, x]));
  assert.equal(by.components.value, "64");
  assert.equal(by.components.sub, "120 versions on 1,830 assets");
  assert.equal(by.components.href, "/components?q=openssl");
  assert.equal(by.affected.value, "900");
  assert.equal(by.affected.sub, "with 2,400 open issues");
  assert.equal(by.affected.href, "/fixes/issues?q=openssl&sort=asset");
  assert.equal(by.critical.href, "/fixes/issues?q=openssl&severity=critical");
  assert.equal(by.urgent.href, "/fixes/issues?q=openssl&priority=P1");
  assert.ok(by.critical.urgent && by.urgent.urgent && !by.components.urgent && !by.affected.urgent);
});

test("one component links to its own page; zero figures link nowhere and are not red", () => {
  const f = searchOverview(results({ components: 1, versions: 2, installed_assets: 3 }));
  const by = Object.fromEntries(f.map((x) => [x.key, x]));
  assert.equal(by.components.href, "/components/1");
  assert.equal(by.components.sub, "2 versions on 3 assets");
  assert.equal(by.critical.href, null);
  assert.equal(by.critical.sub, "none open");
  assert.equal(by.critical.urgent, false);
  assert.equal(by.affected.href, null);
});

test("a version nobody has is said plainly", () => {
  const f = searchOverview(results({ components: 1, versions: 0, installed_assets: 0 }));
  assert.equal(f.find((x) => x.key === "components")?.sub, "none installed at the version searched for");
});

test("the issue links search the same text the counts used", () => {
  const f = searchOverview(results({ components: 1, versions: 1, installed_assets: 1, findings_query: "lodash", open_findings: 1, affected_assets: 1, critical: 1 }));
  assert.equal(f.find((x) => x.key === "critical")?.href, "/fixes/issues?q=lodash&severity=critical");
});

test("no overview without a summary or when nothing installed or open matches", () => {
  assert.deepEqual(searchOverview(results(undefined)), []);
  assert.deepEqual(searchOverview(results({})), []);
  // Open issues alone (an asset name match) still get the overview.
  assert.equal(searchOverview(results({ open_findings: 2, affected_assets: 1 })).length, 4);
});

test("suggestions when nothing matches", () => {
  assert.deepEqual(searchSuggestions("lodash@4.17.20"), ["lodash"]);
  assert.deepEqual(searchSuggestions("@babel/core@7.0.0"), ["@babel/core"]);
  assert.deepEqual(searchSuggestions("openssl 3.0.2"), ["openssl"]);
  assert.deepEqual(searchSuggestions("pkg:npm/%40babel/core@7.0.0"), ["core"]);
  assert.deepEqual(searchSuggestions("pkg:npm/express"), ["express"]);
  assert.deepEqual(searchSuggestions("command injection lodash"), ["command", "injection", "lodash"]);
  assert.deepEqual(searchSuggestions("@babel/core"), []);
  assert.deepEqual(searchSuggestions("CVE-2021-44228"), []);
});
