#!/usr/bin/env node
// npm audit as a release gate: fails on any high or critical advisory that
// is not listed in the allow file, and on any allow entry past its expiry.
//
//   node tools/npm-audit-gate/gate.mjs <package dir> [allow.json]
//
// The allow file is a JSON list of {"id": "GHSA-...", "reason": "...",
// "expires": "YYYY-MM-DD"}. Keep it short: an entry is for an advisory with
// no fixed version that does not affect how the package is used here.
import { execFileSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";

const dir = process.argv[2] || ".";
const allowPath = process.argv[3];
const today = new Date().toISOString().slice(0, 10);
let failed = false;

const allow = new Map();
if (allowPath && existsSync(allowPath)) {
  for (const e of JSON.parse(readFileSync(allowPath, "utf8"))) {
    if (!e.id || !e.reason || !/^\d{4}-\d{2}-\d{2}$/.test(e.expires || "")) {
      console.error(`::error::${allowPath}: every entry needs id, reason and expires (YYYY-MM-DD): ${JSON.stringify(e)}`);
      failed = true;
      continue;
    }
    if (e.expires < today) {
      console.error(`::error::${allowPath}: ${e.id} expired on ${e.expires}; fix it or review the reason and extend it`);
      failed = true;
      continue;
    }
    allow.set(e.id, e);
  }
}

let out;
try {
  out = execFileSync("npm", ["audit", "--json"], { cwd: dir, encoding: "utf8", maxBuffer: 64 << 20 });
} catch (err) {
  out = err.stdout; // npm audit exits non-zero when it finds anything
  if (!out) throw err;
}
const report = JSON.parse(out);
if (report.error) {
  console.error(`::error::npm audit failed: ${JSON.stringify(report.error)}`);
  process.exit(1);
}

const seen = new Set();
for (const [name, v] of Object.entries(report.vulnerabilities || {})) {
  for (const via of v.via || []) {
    if (typeof via !== "object") continue; // reached through another package
    if (via.severity !== "high" && via.severity !== "critical") continue;
    const id = (via.url || "").split("/").pop() || String(via.source);
    if (seen.has(`${name} ${id}`)) continue;
    seen.add(`${name} ${id}`);
    if (allow.has(id)) {
      console.log(`allowed until ${allow.get(id).expires}: ${id} ${name} (${allow.get(id).reason})`);
      continue;
    }
    console.error(`::error::${via.severity}: ${id} in ${name} ${via.range || ""}: ${via.title} (fix available: ${v.fixAvailable ? "yes" : "no"})`);
    failed = true;
  }
}
if (failed) process.exit(1);
console.log(`npm audit gate passed for ${dir}: no high or critical advisories outside the allow list`);
