// Groups search results the way someone investigates (components/Search.tsx):
// Vite compiles the .tsx (node --test cannot).
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createServer, type ViteDevServer } from "vite";
import type { SearchResults, SearchVuln } from "./api.ts";

let vite: ViteDevServer;
type Section = { id: string; title: string; items: { key: string }[]; more: boolean };
let searchSections: (r: SearchResults, opt?: { order?: "rank" | "investigate" }) => Section[];

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  ({ searchSections } = (await vite.ssrLoadModule("/src/components/Search.tsx")) as { searchSections: typeof searchSections });
});
after(async () => {
  await vite?.close();
});

const vuln = (key: string, kind: SearchVuln["kind"], rank: 0 | 1 | 2 = 0): SearchVuln => ({
  key,
  kind,
  rank,
  title: "",
  severity: "high",
  score: null,
  known_exploited: false,
  open_findings: kind ? 1 : 0,
  resolved_findings: 0,
  affected_assets: kind ? 1 : 0,
  assets: [],
  components: [],
});

const r: SearchResults = {
  query: "openssl",
  vulnerabilities: [vuln("CVE-2024-1", "vulnerability"), vuln("CVE-2024-2", "")],
  findings: [{ key: "CVE-2024-3", kind: "vulnerability", title: "openssl overflow", rank: 2, severity: "high", score: null, open_findings: 1, affected_assets: 1, assets: [] }],
  assets: [{ id: 1, kind: "host", name: "openssl-build", environment: "", owner_team: "", collection_status: "ok", last_seen: "", rank: 1, match_scheme: "", match_value: "", open_findings: 0 }],
  components: [{ id: 2, purl_key: "pkg:deb/ubuntu/openssl", type: "deb", namespace: "ubuntu", name: "openssl", rank: 2, asset_count: 1, versions: ["3.0.2"], open_findings: 0, assets: [], version_assets: 0 }],
  teams: [{ id: 3, name: "openssl team", email: "", rank: 0, asset_count: 0, open_findings: 0 }],
  members: [],
  more: { vulnerabilities: true },
};

test("the results page orders groups for an investigation, whatever matched best", () => {
  const s = searchSections(r, { order: "investigate" });
  assert.deepEqual(
    s.map((x) => x.title),
    ["Assets", "Components", "Vulnerabilities", "Advisories", "Teams"],
  );
  // Affected keys and title matches are vulnerabilities; an advisory that affects nothing here is an advisory.
  assert.deepEqual(s[2].items.map((i) => i.key), ["v:CVE-2024-1", "f:CVE-2024-3:openssl overflow"]);
  assert.deepEqual(s[3].items.map((i) => i.key), ["v:CVE-2024-2"]);
  // A cut vulnerability list may have cut advisories too.
  assert.ok(s[2].more && s[3].more);
});

test("the dropdown still puts the best match first", () => {
  assert.equal(searchSections(r)[0].title, "Vulnerabilities");
});
