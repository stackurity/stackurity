// Browser checks of policy gates, at desktop and phone widths. The CI
// estate has no policies, so the policies and violations are served here as
// GET /gate-policies and GET /gate-policies/violations would send them:
//   - Settings → Policy gates lists each policy with its rule, mode, where
//     it is off ("Off for 2 projects") and its violations;
//   - Add policy opens the form in warn mode; Enforce says it needs a paid
//     plan (Pro badge and notice) and can still be picked;
//   - Fixes → Policy violations lists policy, mode, asset, component and
//     reason, a filter shows as a chip, and Clear all removes it;
//   - the Dashboard's Needs your attention has a policy violations row;
//   - a violation row asks for an exception (the form opens above the
//     table, the request is sent and a notice says so), one already asked
//     says it is waiting, and exceptions in force are listed below;
//   - Approvals → Policy exceptions lists a request and approves it;
//   - no horizontal scroll on any of them.
// The settings and violations routes are also in layout.mjs's sweep (they
// come from App.tsx).
//
//   node policygates.mjs <base url> [email] [password]
import { chromium } from "playwright";

const [base = "http://127.0.0.1:8080", email = "ui@example.com", password = "UI-test-password-1."] = process.argv.slice(2);
const failures = [];
const ok = (cond, what) => {
  console.log(`${cond ? "PASS" : "FAIL"} ${what}`);
  if (!cond) failures.push(what);
};

const policy = (over) => ({
  id: 3,
  name: "No old criticals",
  description: "",
  kind: "finding_age",
  params: { min_severity: "critical", max_days: 14, only_fixable: true },
  filters: { asset_kinds: [], environments: ["production"], exposure: "any", tags: [] },
  mode: "warn",
  owner_project_id: null,
  owner_asset_id: null,
  inherits_policy_id: null,
  rule_version: 1,
  created_by_name: "UI",
  created_at: "2026-11-16T09:00:00Z",
  updated_by_name: "UI",
  updated_at: "2026-11-16T09:00:00Z",
  off_projects: [1, 2],
  off_assets: [],
  ...over,
});
const policies = [
  policy(),
  policy({ id: 4, name: "No known exploited", kind: "known_exploited", params: {}, mode: "enforce", off_projects: [], filters: { asset_kinds: [], environments: [], exposure: "exposed", tags: [] } }),
];
const violation = (over) => ({
  policy_id: 3,
  policy_name: "No old criticals",
  mode: "warn",
  kind: "finding_age",
  asset_id: 1,
  asset_name: "demo-web-1",
  reason: "CVE-2026-0042 in zlib 1.2.11 (critical) has been open for 30 days; the limit is 14",
  finding_id: 9101,
  component: "zlib 1.2.11",
  key: "CVE-2026-0042",
  link: "/findings/9101",
  violation_key: "finding:9101",
  ...over,
});
const violations = [
  violation(),
  violation({ asset_id: 2, asset_name: "demo-web-2", finding_id: 9102, violation_key: "finding:9102", link: "/findings/9102" }),
  violation({ policy_id: 4, policy_name: "No known exploited", mode: "enforce", kind: "known_exploited", reason: "CVE-2026-1234 in openssl 3.0.2 is known to be exploited", component: "openssl 3.0.2", finding_id: 9103, violation_key: "finding:9103", link: "/findings/9103" }),
];

const soon = new Date(Date.now() + 10 * 86_400_000).toISOString();
const exception = (over) => ({
  id: 12,
  policy_id: 3,
  policy_name: "No old criticals",
  rule_version: 1,
  target_kind: "finding",
  asset_id: 2,
  asset_name: "demo-web-2",
  finding_id: 9102,
  leak_id: null,
  component_key: "",
  target_label: "CVE-2026-0042 in zlib 1.2.11",
  reason: "mitigated",
  note: "A WAF rule blocks it",
  status: "pending",
  requested_by_id: 2,
  requested_by: "Eng",
  requested_at: "2026-11-16T09:00:00Z",
  requested_expires_at: soon,
  decided_by_id: null,
  decided_by: "",
  decided_at: null,
  decision_note: "",
  expires_at: null,
  ended_at: null,
  ended_by: "",
  end_reason: "",
  end_note: "",
  ...over,
});
const exceptions = [
  exception(),
  exception({ id: 13, policy_id: 4, policy_name: "No known exploited", asset_id: 3, asset_name: "demo-db-1", status: "approved", decided_by: "Sec", decided_at: "2026-11-16T10:00:00Z", expires_at: soon }),
];

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
  await page.route("**/api/v1/gate-policies", (r) =>
    r.request().method() === "GET" ? r.fulfill({ json: { items: policies, total: policies.length } }) : r.fulfill({ status: 201, json: policies[0] }),
  );
  await page.route("**/api/v1/gate-policies/violations*", (r) => {
    const q = new URL(r.request().url()).searchParams;
    const items = violations.filter((v) => !q.get("policy_id") || String(v.policy_id) === q.get("policy_id"));
    return r.fulfill({ json: { items, total: items.length } });
  });
  let asked = null;
  let decided = null;
  await page.route("**/api/v1/gate-policies/exceptions**", (r) => {
    const req = r.request();
    const url = new URL(req.url());
    if (req.method() === "POST" && url.pathname.endsWith("/decision")) {
      decided = req.postDataJSON();
      return r.fulfill({ json: { ...exceptions[0], status: "approved", decided_by: "UI", decided_at: new Date().toISOString(), expires_at: soon } });
    }
    if (req.method() === "POST") {
      asked = req.postDataJSON();
      return r.fulfill({ status: 201, json: exception({ id: 21, asset_id: asked.asset_id, asset_name: "demo-web-1", finding_id: asked.finding_id, note: asked.note }) });
    }
    const status = url.searchParams.get("status");
    const items = exceptions.filter((x) => !status || status === "all" || x.status === status);
    return r.fulfill({ json: { items, total: items.length, can_decide: true } });
  });
  const noScroll = async (what) =>
    ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), `${tag} no horizontal scroll on ${what}`);

  // Settings → Policy gates
  await page.goto(base + "/settings/policy-gates");
  await page.getByRole("heading", { name: "Organisation policies" }).waitFor();
  const list = await page.locator("main, #main").first().innerText();
  ok(list.includes("No old criticals") && list.includes("Off for 2 projects"), `${tag} a policy says where it is off`);
  ok(list.includes("Critical vulnerabilities open more than 14 days"), `${tag} a policy says its rule in words`);
  ok(/2 violations on 2 assets/.test(list), `${tag} a policy counts its violations`);
  ok(list.includes("Applies everywhere") && list.includes("internet-facing"), `${tag} the second policy's scope and filters`);
  await noScroll("Settings → Policy gates");
  await page.getByRole("button", { name: "Add policy" }).first().click();
  const form = page.locator('form[aria-label="New policy"]');
  await form.waitFor();
  ok(await form.getByRole("radio", { name: /^Warn/ }).isChecked(), `${tag} a new policy starts in warn`);
  const formText = await form.innerText();
  ok(/Pro/.test(formText) && /part of Stackurity Pro/.test(formText), `${tag} enforce shows it needs a paid plan`);
  ok(formText.includes("not enforced on this plan") || formText.includes("checks then pass"), `${tag} enforce on the free plan says checks still pass`);
  await form.getByRole("radio", { name: /^Enforce/ }).check();
  ok(/Enforce on this plan/.test(await form.locator(".card-footer-status").innerText()), `${tag} enforce can be picked on the free plan, and the footer says what it means`);
  await noScroll("the policy form");

  // Fixes → Policy violations
  await page.goto(base + "/fixes/policy-violations");
  await page.getByRole("heading", { name: "Policy violations" }).waitFor();
  const vt = await page.locator("main, #main").first().innerText();
  ok(vt.includes("3 violations on 2 assets"), `${tag} the violations page counts them`);
  ok(vt.includes("known to be exploited") && vt.includes("openssl 3.0.2"), `${tag} a violation shows its reason and component`);
  ok(await page.getByRole("link", { name: "Open the issue" }).first().isVisible(), `${tag} each violation links to its issue`);
  await noScroll("the violations page");
  await page.selectOption("#pv-policy", "4");
  await page.getByText("Policy: No known exploited").waitFor();
  ok(await page.locator(".filter-chip").count() === 1, `${tag} the policy filter shows as a chip`);
  await page.getByRole("button", { name: "Clear all" }).click();
  ok(await page.locator(".filter-chip").count() === 0, `${tag} Clear all removes it`);

  // Exceptions from the violations page.
  const visible = (sel) => page.locator(sel).filter({ visible: true });
  ok(await visible(':text("is waiting for a decision")').count() === 1, `${tag} a violation with a request says it is waiting`);
  ok((await page.locator(".exceptions-in-force summary").innerText()).includes("1 exception is in force"), `${tag} exceptions in force are listed below`);
  await visible('button:text-is("Ask for an exception")').first().click();
  const askForm = page.locator('form[aria-label="Ask for an exception to No old criticals"]');
  await askForm.waitFor();
  ok(await askForm.getByRole("radio", { name: /^This issue only/ }).isChecked(), `${tag} the form covers this issue by default`);
  await noScroll("the exception form");
  await askForm.getByRole("button", { name: "Ask for an exception" }).click();
  ok((await askForm.getByRole("alert").innerText()).includes("Say why"), `${tag} the form asks why first`);
  await askForm.getByLabel("Why", { exact: true }).fill("Behind the VPN only");
  await askForm.getByRole("button", { name: "Ask for an exception" }).click();
  await page.getByText("Exception #21 asked for").waitFor();
  ok(asked?.policy_id === 3 && asked?.target_kind === "finding" && asked?.finding_id === 9101 && asked?.note === "Behind the VPN only" && Boolean(asked?.expires_at),
    `${tag} the request names the policy, the issue, why and an end date`);

  // Approvals → Policy exceptions.
  await page.goto(base + "/approvals?tab=policy");
  await page.getByRole("heading", { name: "Approvals" }).waitFor();
  const inbox = page.locator('ul[aria-label="Policy exceptions"]');
  await inbox.waitFor();
  ok((await inbox.innerText()).includes("Waiting for a decision"), `${tag} the pending exception is in the inbox`);
  await noScroll("Approvals → Policy exceptions");
  await inbox.getByRole("button", { name: "Approve" }).click();
  await page.getByText("Exception #12 approved").waitFor();
  ok(decided?.decision === "approve", `${tag} approving sends the decision`);

  // Dashboard: a row in Needs your attention.
  await page.goto(base + "/");
  await page.locator("#dash-needs").waitFor();
  await page.getByText("3 policy violations on 2 assets").waitFor().catch(() => {});
  ok(await page.getByText("3 policy violations on 2 assets").isVisible(), `${tag} the Dashboard has a policy violations row`);
  ok((await page.getByRole("link", { name: "Open policy violations" }).getAttribute("href")) === "/fixes/policy-violations", `${tag} the row opens the violations page`);
  await ctx.close();
}
await browser.close();
if (failures.length) {
  console.log(`\n${failures.length} failed`);
  process.exit(1);
}
