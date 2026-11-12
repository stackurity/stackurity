import { test } from "node:test";
import assert from "node:assert/strict";
import { nvdUrl, osvUrl, readMoreLinks, readMoreUrl } from "./advisoryLinks.ts";
import type { Advisory } from "./api.ts";

test("read-more addresses must be https pages on advisory sites", () => {
  for (const ok of [
    "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
    "https://osv.dev/vulnerability/GHSA-xxxx-xxxx-xxxx",
    "https://github.com/advisories/GHSA-6jjj-mmmm-pppp",
    "https://www.cve.org/CVERecord?id=CVE-2024-3094",
    "https://cve.org/CVERecord?id=CVE-2024-3094",
    "https://ubuntu.com/security/CVE-2024-3094",
    "https://ubuntu.com/security/notices/USN-6123-1",
    "https://security-tracker.debian.org/tracker/CVE-2024-3094",
    "https://access.redhat.com/security/cve/CVE-2024-3094",
    "https://NVD.NIST.GOV/vuln/detail/CVE-2024-3094",
  ]) {
    assert.ok(readMoreUrl(ok), ok);
  }
  for (const bad of [
    "http://nvd.nist.gov/vuln/detail/CVE-2024-3094",
    "https://evil.example/CVE-2024-3094",
    "https://nvd.nist.gov.evil.example/x",
    "https://evil.example/?u=https://nvd.nist.gov/",
    "https://github.com/someone/repo/commit/abc",
    "https://github.com/advisories/",
    "https://github.com/someone/advisories/x",
    "https://ubuntu.com/download",
    "https://ubuntu.com/securityx/1",
    "https://user:pw@nvd.nist.gov/vuln/detail/CVE-1",
    "https://nvd.nist.gov:8443/vuln/detail/CVE-1",
    "https://www.redhat.com/security",
    "javascript:alert(1)",
    "data:text/html,x",
    "//nvd.nist.gov/x",
    "/findings/1",
    "",
    null,
    undefined,
  ]) {
    assert.equal(readMoreUrl(bad), null, String(bad));
  }
  assert.deepEqual(readMoreUrl("https://GitHub.com/advisories/GHSA-1"), { href: "https://github.com/advisories/GHSA-1", domain: "github.com" });
});

const adv = (a: Partial<Advisory>): Advisory =>
  ({ id: "", feed: "osv", group_key: "", aliases: null, summary: "", severity: "", score: null, vector: "", severity_source: "", published: null, modified: "", withdrawn: null, references: null, known_exploited: false, ...a }) as Advisory;

test("read-more links: built pages first, stored ones on the allowlist, no repeats", () => {
  const links = readMoreLinks([
    adv({
      id: "GHSA-6jjj-mmmm-pppp",
      aliases: ["CVE-2024-3094"],
      references: [
        { type: "WEB", url: "https://nvd.nist.gov/vuln/detail/CVE-2024-3094" },
        { type: "ADVISORY", url: "https://security-tracker.debian.org/tracker/CVE-2024-3094" },
        { type: "WEB", url: "https://evil.example/pwn" },
        { type: "WEB", url: "http://access.redhat.com/x" },
        { type: "WEB" },
      ],
    }),
  ]);
  assert.deepEqual(links, [
    { href: osvUrl("GHSA-6jjj-mmmm-pppp"), domain: "osv.dev", label: "GHSA-6jjj-mmmm-pppp" },
    { href: nvdUrl("CVE-2024-3094"), domain: "nvd.nist.gov", label: "CVE-2024-3094" },
    { href: "https://security-tracker.debian.org/tracker/CVE-2024-3094", domain: "security-tracker.debian.org", label: "CVE-2024-3094" },
  ]);
  const many = readMoreLinks([adv({ id: "X-1", references: Array.from({ length: 20 }, (_, i) => ({ url: `https://osv.dev/vulnerability/Y-${i}` })) })], 4);
  assert.equal(many.length, 4);
});
