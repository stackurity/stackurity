// Browser checks of verified closure on the finding page, at desktop and
// phone widths. The CI estate has no feeds, so the closed findings are
// served here as GET /findings/{id} would send them:
//   - a fixed finding says "Verified fixed" and lists its proof: the
//     version before and after, the check that saw it, the remediation
//     plan; without the paid fix loop, time to fix against the SLA is a
//     locked "Pro" line;
//   - a finding Stackurity lost sight of says "Disappeared (not verified)",
//     why, and that it is not counted as remediation;
//   - no horizontal scroll.
//
//   node closure.mjs <base url> [email] [password]
import { chromium } from "playwright";

const [base = "http://127.0.0.1:8080", email = "ui@example.com", password = "UI-test-password-1."] = process.argv.slice(2);
const failures = [];
const ok = (cond, what) => {
  console.log(`${cond ? "PASS" : "FAIL"} ${what}`);
  if (!cond) failures.push(what);
};

const finding = (id, over) => ({
  id,
  kind: "vulnerability",
  key: "CVE-2021-23337",
  asset_id: 1,
  asset_name: "demo-web-1",
  component_id: 1,
  component_name: "lodash",
  version: "4.17.15",
  verification: "confirmed",
  status: "resolved",
  severity: "high",
  score: 7.2,
  title: "Command injection in lodash",
  fixed_version: "4.17.21",
  sources: ["GHSA-35jh-r3h4-6jhm"],
  evidence: {},
  first_seen: "2026-11-01T09:00:00Z",
  last_seen: "2026-11-10T09:00:00Z",
  resolved_at: "2026-11-10T09:05:00Z",
  known_exploited: false,
  state: "new",
  priority: "P2",
  fix_due: "2026-11-15T09:00:00Z",
  ...over,
});
const fixed = finding(9101, {
  resolution: "fixed by remediation plan #7 (upgraded to 4.17.21)",
  resolution_kind: "remediated",
  resolution_detail: { plan_id: 7, version: "4.17.21", from_version: "4.17.15", to_inventory_id: 55, collection_id: 42, method: "agent", checked_at: "2026-11-10T09:00:00Z" },
});
const gone = finding(9102, {
  resolution: "disappeared: Stackurity can no longer see this asset, so the fix was not verified",
  resolution_kind: "disappeared",
  resolution_detail: { from_version: "4.17.15", collection_id: 43, method: "repository", checked_at: "2026-11-10T09:00:00Z" },
});

const browser = await chromium.launch();
for (const width of [1280, 390]) {
  const tag = `${width}px`;
  const ctx = await browser.newContext({ viewport: { width, height: 860 } });
  ctx.setDefaultTimeout(20000);
  const page = await ctx.newPage();
  await page.goto(base + "/login");
  await page.fill("#login-email", email);
  await page.fill("#login-password", password);
  await page.click('form[aria-labelledby="login-title"] button[type=submit]');
  await page.locator("nav[aria-label=Main]").waitFor({ state: "attached" });
  for (const f of [fixed, gone]) {
    await page.route(`**/api/v1/findings/${f.id}`, (r) => r.fulfill({ json: { finding: f, advisories: [], why: null } }));
  }

  await page.goto(base + "/findings/9101");
  const head = page.locator(".badges").first();
  await page.getByText("Verified fixed").first().waitFor();
  ok(await head.getByText("Verified fixed").isVisible(), `${tag} a fixed finding has the Verified fixed badge`);
  const notice = page.locator(".alert-success").first();
  const text = await notice.innerText();
  ok(/Version before\s*4\.17\.15/.test(text) && /Version after\s*4\.17\.21/.test(text), `${tag} the proof lists the versions before and after`);
  ok(/Seen by\s*the agent's report/.test(text) && text.includes("collection #42"), `${tag} the proof names the check that saw it`);
  ok(/Fixed by\s*remediation plan #7/.test(text), `${tag} the proof names the remediation plan`);
  ok(/Time to fix/.test(text) && (/Pro/.test(text) || /within the fix-by date/.test(text)), `${tag} time to fix is shown, or locked on the free plan`);
  ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), `${tag} no horizontal scroll on a fixed finding`);

  await page.goto(base + "/findings/9102");
  await page.getByText("Disappeared (not verified)").first().waitFor();
  const warn = await page.locator(".alert-warn").first().innerText();
  ok(warn.includes("Disappeared (not verified)") && warn.includes("not counted as remediation"), `${tag} a disappeared finding says it was not verified and is not counted`);
  ok(/Lost sight on\s*.*by a repository scan/.test(warn), `${tag} it says when Stackurity lost sight of the asset`);
  ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), `${tag} no horizontal scroll on a disappeared finding`);
  await ctx.close();
}
await browser.close();
if (failures.length) {
  console.log(`\n${failures.length} failed`);
  process.exit(1);
}
