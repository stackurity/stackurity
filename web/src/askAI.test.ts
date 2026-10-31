// Run with `npm test` (node --test, TypeScript types stripped).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  advisoryId,
  askFromAsset,
  askFromFinding,
  askFromFixGroup,
  assistantsFor,
  claudeDesktopLink,
  publicToken,
  readDismissed,
  writeDismissed,
  type AskQuestion,
} from "./askAI.ts";

// Everything about the organisation a record can carry. None of it may reach
// the question, whatever the builder.
const SECRETS = [
  "db-prod-7.acme.internal",
  "db-prod-7",
  "10.20.30.40",
  "fd00:1:2:3::7",
  "/srv/billing/package-lock.json",
  "billing-api",
  "production-eu",
  "Payments Team",
  "ops@acme.example",
  "acme",
];

function assertNoSecrets(q: AskQuestion | null) {
  assert.ok(q, "a question");
  for (const s of SECRETS) assert.ok(!q.text.toLowerCase().includes(s.toLowerCase()), `leaked ${s}: ${q.text}`);
  for (const s of SECRETS) assert.ok(!q.about.toLowerCase().includes(s.toLowerCase()), `leaked ${s} in about`);
}

// A finding as the API returns it, internal fields filled with the secrets.
const finding = {
  id: 9,
  kind: "vulnerability",
  key: "cve-2024-6387",
  asset_id: 3,
  asset_name: "db-prod-7.acme.internal",
  asset_kind: "host",
  environment: "production-eu",
  component_id: 4,
  component_name: "openssh-server",
  component_type: "deb",
  version: "1:8.9p1-3ubuntu0.6",
  fixed_version: "1:8.9p1-3ubuntu0.10",
  location: "/srv/billing/package-lock.json",
  title: "regreSSHion on db-prod-7 (Payments Team)",
  evidence: { ip: "10.20.30.40", ipv6: "fd00:1:2:3::7", hostname: "db-prod-7", owner: "ops@acme.example" },
  assignee_email: "ops@acme.example",
  team_name: "Payments Team",
};

test("finding: advisory id, package@version and fixed version, nothing internal", () => {
  const q = askFromFinding(finding);
  assertNoSecrets(q);
  assert.match(q!.text, /CVE-2024-6387/);
  assert.match(q!.text, /openssh-server 1:8\.9p1-3ubuntu0\.6 \(deb\)/);
  assert.match(q!.text, /fixed in 1:8\.9p1-3ubuntu0\.10/);
  assert.equal(q!.about, "CVE-2024-6387");
});

test("finding: end of life asks about the product and version", () => {
  const q = askFromFinding({ ...finding, kind: "end_of_life", key: "eol:db-prod-7:ubuntu", component_name: "ubuntu", component_type: "os", version: "20.04", fixed_version: "" });
  assertNoSecrets(q);
  assert.match(q!.text, /^ubuntu 20\.04 \(os\) has reached end of life/);
});

test("finding: a key that is not an advisory id is not sent", () => {
  const q = askFromFinding({ ...finding, key: "acme-internal-42" });
  assertNoSecrets(q);
  assert.match(q!.text, /this vulnerability/);
});

test("finding: internal-looking package values are dropped, and a package named like the asset drops the question", () => {
  assert.equal(askFromFinding({ ...finding, component_name: "10.20.30.40" }), null);
  assert.equal(askFromFinding({ ...finding, component_name: "billing-api", asset_name: "billing-api" }), null);
  const q = askFromFinding({ ...finding, version: "db-prod-7.acme.internal", fixed_version: "/srv/x" });
  assertNoSecrets(q);
  assert.match(q!.text, /openssh-server \(deb\) is affected, with no fixed version listed/);
});

const group = {
  id: "3:pkg:lodash",
  kind: "package_upgrade",
  title: "Upgrade lodash on billing-api",
  action: "cd /srv/billing && npm install lodash@4.17.21",
  asset_id: 3,
  asset_name: "billing-api",
  asset_kind: "application",
  environment: "production-eu",
  app_dir: "/srv/billing",
  component: "lodash",
  from_version: "4.17.15",
  to_version: "4.17.21",
  target_version: "4.17.21",
  places: [{ group_id: "7:pkg:lodash", asset_id: 7, asset_name: "db-prod-7", asset_kind: "host", app_dir: "/srv/billing/package-lock.json", environment: "production-eu", finding_count: 2 }],
};

test("fix card: package from and to, nothing internal (no title, action, asset or places)", () => {
  const q = askFromFixGroup(group);
  assertNoSecrets(q);
  assert.match(q!.text, /upgrade of lodash from 4\.17\.15 to 4\.17\.21/);
});

test("fix card: OS update bundles name no package, so no question", () => {
  assert.equal(askFromFixGroup({ ...group, kind: "security_updates", component: "" }), null);
});

test("asset: operating system and the waiting upgrades, never the asset", () => {
  const q = askFromAsset({ name: "db-prod-7.acme.internal", internal: ["db-prod-7", "10.20.30.40"], os_name: "Ubuntu 22.04.4 LTS", environment: "production-eu" }, [
    group,
    { ...group, component: "openssl", from_version: "3.0.2", to_version: "3.0.13", target_version: "" },
    { ...group, component: "", kind: "security_updates" },
  ]);
  assertNoSecrets(q);
  assert.match(q!.text, /runs Ubuntu 22\.04\.4 LTS\. It needs these upgrades: lodash 4\.17\.15 → 4\.17\.21; openssl 3\.0\.2 → 3\.0\.13\./);
  assert.equal(askFromAsset({ name: "x", os_name: "" }, []), null);
});

test("publicToken and advisoryId", () => {
  for (const bad of ["10.0.0.1", "http://x.test", "/etc/passwd", "C:\\x", "a@b.example", "web.corp", "db.internal", "x".repeat(200), "a;rm -rf", "<b>"])
    assert.equal(publicToken(bad), "", bad);
  for (const ok of ["@types/node", "org.apache.logging.log4j:log4j-core", "1:8.9p1-3ubuntu0.6", "socket.io", "Ubuntu 22.04.4 LTS", "2.0.0+build.1"])
    assert.equal(publicToken(ok), ok, ok);
  assert.equal(advisoryId("cve-2021-44228"), "CVE-2021-44228");
  assert.equal(advisoryId("GHSA-jfh8-c2jp-5v3q"), "GHSA-jfh8-c2jp-5v3q");
  assert.equal(advisoryId("PYSEC-2023-117"), "PYSEC-2023-117");
  assert.equal(advisoryId("WEB-01"), "");
  assert.equal(advisoryId("eol:ubuntu:20.04"), "");
});

test("Claude Desktop link: the documented claude://claude.ai/new?q= prefill, URL-encoded", () => {
  const link = claudeDesktopLink({ text: "Explain CVE-2024-6387 & more?", about: "" });
  assert.equal(link, "claude://claude.ai/new?q=Explain%20CVE-2024-6387%20%26%20more%3F");
});

test("assistants offered follow what is connected", () => {
  assert.deepEqual(assistantsFor([]), []);
  assert.deepEqual(assistantsFor([{ client_name: "Claude", redirect_host: "claude.ai" }]), ["claude"]);
  assert.deepEqual(assistantsFor([{ client_name: "ChatGPT", redirect_host: "chatgpt.com" }]), ["chatgpt"]);
  assert.deepEqual(assistantsFor([{ client_name: "Cursor", redirect_host: "localhost" }]), ["claude", "chatgpt"]);
});

test("dismissal is per person and survives a storage that throws", () => {
  const m = new Map<string, string>();
  const store = { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), removeItem: (k: string) => void m.delete(k) };
  assert.equal(readDismissed(1, store), false);
  writeDismissed(1, true, store);
  assert.equal(readDismissed(1, store), true);
  assert.equal(readDismissed(2, store), false);
  writeDismissed(1, false, store);
  assert.equal(readDismissed(1, store), false);
  const broken = {
    getItem: () => {
      throw new Error("blocked");
    },
    setItem: () => {
      throw new Error("blocked");
    },
    removeItem: () => {
      throw new Error("blocked");
    },
  };
  assert.equal(readDismissed(1, broken), false);
  writeDismissed(1, true, broken);
});

test("asset: a package that shares a name with an asset value drops the question", () => {
  assert.equal(askFromAsset({ name: "web", os_name: "Debian 12", internal: ["postgres"] }, [{ ...group, component: "postgres" }]), null);
});
