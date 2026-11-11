import { test } from "node:test";
import assert from "node:assert/strict";
import { sourceCheckCommand, sourceFixOf } from "./sourceFix.ts";

// The evidence the matcher stores for telnet 0.17+2.5-3ubuntu4 (built from
// inetutils 2:2.5-3ubuntu4) against UBUNTU-CVE-2026-24061.
const telnet = {
  component_name: "ubuntu/telnet",
  fixed_version: "2:2.5-3ubuntu4.1",
  evidence: { osv_package: "inetutils", match: { rule: "range", source_version: "2:2.5-3ubuntu4" } },
};

test("a fix named by the source package's version", () => {
  const s = sourceFixOf(telnet);
  assert.deepEqual(s, { binary: "telnet", source: "inetutils", sourceVersion: "2:2.5-3ubuntu4", fixed: "2:2.5-3ubuntu4.1" });
  assert.equal(sourceCheckCommand(s!), "dpkg-query -W -f='${source:Version}\\n' telnet");
});

test("the binary's own version, older evidence and other packages", () => {
  for (const evidence of [
    { osv_package: "inetutils", match: { rule: "range" } },
    { osv_package: "inetutils" },
    { match: { source_version: "2:2.5-3ubuntu4" } },
    null,
  ])
    assert.equal(sourceFixOf({ ...telnet, evidence }), null);
});
