import { test } from "node:test";
import assert from "node:assert/strict";
import { fixedVersionRows, fixLines, lineComponents, type ComponentFix } from "./incidentFix.ts";

// The v0.19.0 demo's CVE-2026-18924 in curl: Ubuntu packages fixed, the
// Debian one not.
const curl: ComponentFix[] = [
  { component: "ubuntu/curl", type: "deb", fixed_versions: ["7.81.0-1ubuntu1.29"], assets: 2, unfixed: 0 },
  { component: "debian/curl", type: "deb", fixed_versions: [], assets: 1, unfixed: 1 },
  { component: "ubuntu/libcurl4", type: "deb", fixed_versions: ["7.81.0-1ubuntu1.29"], assets: 1, unfixed: 0 },
];

test("an Ubuntu version is never offered for a Debian package", () => {
  const lines = fixLines(curl)!;
  assert.equal(lines.length, 2);
  assert.equal(lines[0].kind, "fix");
  assert.deepEqual(lines[0].components.map((c) => c.name), ["ubuntu/curl", "ubuntu/libcurl4"]);
  assert.equal(lineComponents(lines[0]), "ubuntu/curl (2 assets), ubuntu/libcurl4 (1 asset)");
  assert.equal(lines[0].text, "upgrade to 7.81.0-1ubuntu1.29 or later.");
  assert.equal(lines[1].kind, "none");
  assert.deepEqual(lines[1].components, [{ name: "debian/curl", assets: 1 }]);
  assert.match(lines[1].text, /^no fixed version is published yet for Debian\. Watch the advisory and consider mitigations\.$/);
  assert.doesNotMatch(lines[1].text, /ubuntu/);
  assert.deepEqual(fixedVersionRows(lines), [
    { components: "ubuntu/curl, ubuntu/libcurl4", versions: "7.81.0-1ubuntu1.29" },
    { components: "debian/curl", versions: "none yet" },
  ]);
});

test("several release lines and a partial fix are said honestly", () => {
  const lines = fixLines([
    { component: "ubuntu/openssl", type: "deb", fixed_versions: ["3.0.2-0ubuntu1.18", "3.0.13-0ubuntu3.4"], assets: 3, unfixed: 0 },
    { component: "debian/openssl", type: "deb", fixed_versions: ["3.0.15-1~deb12u1"], assets: 3, unfixed: 1 },
    { component: "lodash", type: "npm", fixed_versions: [], assets: 1, unfixed: 1 },
  ])!;
  assert.equal(lines[0].kind, "per_release");
  assert.match(lines[0].text, /the version for each asset's release: 3\.0\.2-0ubuntu1\.18 \/ 3\.0\.13-0ubuntu3\.4 or later\. See the Fix column/);
  assert.equal(lines[1].kind, "partial");
  assert.match(lines[1].text, /3\.0\.15-1~deb12u1 or later on the 2 assets where it is published\. No fixed version is published yet for the other 1 asset/);
  assert.equal(lines[2].text, "no fixed version is published yet. Watch the advisory and consider mitigations.");
});

test("no component_fixes falls back", () => {
  assert.equal(fixLines(undefined), null);
  assert.equal(fixLines([]), null);
});

// Debian/Ubuntu binary packages whose fix is named by their source package's
// version: apt has no telnet 2:2.5-3ubuntu4.1, so the advice names the source
// build, and a binary whose version is the source's keeps its own line.
test("a fix named by source version names the source build", () => {
  const lines = fixLines([
    { component: "ubuntu/telnet", type: "deb", fixed_versions: ["2:2.5-3ubuntu4.1"], assets: 2, unfixed: 0, source_package: "inetutils" },
    { component: "ubuntu/inetutils-telnetd", type: "deb", fixed_versions: ["2:2.5-3ubuntu4.1"], assets: 1, unfixed: 0 },
  ])!;
  assert.equal(lines.length, 2);
  assert.equal(lines[0].text, "upgrade to a build from inetutils 2:2.5-3ubuntu4.1 or later.");
  assert.equal(lines[1].text, "upgrade to 2:2.5-3ubuntu4.1 or later.");
  assert.deepEqual(fixedVersionRows(lines), [
    { components: "ubuntu/telnet", versions: "inetutils 2:2.5-3ubuntu4.1" },
    { components: "ubuntu/inetutils-telnetd", versions: "2:2.5-3ubuntu4.1" },
  ]);
  const per = fixLines([
    { component: "ubuntu/telnet", type: "deb", fixed_versions: ["2:2.4-2ubuntu0.1", "2:2.5-3ubuntu4.1"], assets: 3, unfixed: 0, source_package: "inetutils" },
  ])!;
  assert.match(per[0].text, /^upgrade to a build from inetutils at the version for each asset's release: 2:2\.4-2ubuntu0\.1 \/ 2:2\.5-3ubuntu4\.1 or later\./);
  const part = fixLines([
    { component: "ubuntu/telnet", type: "deb", fixed_versions: ["2:2.5-3ubuntu4.1"], assets: 3, unfixed: 1, source_package: "inetutils" },
  ])!;
  assert.match(part[0].text, /^upgrade to a build from inetutils 2:2\.5-3ubuntu4\.1 or later on the 2 assets where it is published\./);
});
