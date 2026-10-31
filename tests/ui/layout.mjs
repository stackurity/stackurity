// Layout checks over every route of the dashboard, at desktop and phone
// widths (the owner's rule: a UI bug becomes a test over every page).
//
//   node layout.mjs <base url> [email] [password]
//
// For every route and width:
//   - scrolled to the very bottom, the sidebar still covers the screen from
//     top to bottom (it once stopped part-way and scrolled away);
//   - no more than 24 px of empty space lies below the page's last element
//     (a hidden data table once left a 471 px band);
// plus EXTRA_CHECKS in routes.mjs. Fails, listing every offending route.
import { chromium } from "playwright";
import { fileURLToPath } from "node:url";
import { appRoutes, EXTRA_CHECKS, fillParams, WIDTHS } from "./routes.mjs";

const [base = "http://127.0.0.1:8080", email = "ui@example.com", password = "ui-test-password-1"] = process.argv.slice(2);
const app = fileURLToPath(new URL("../../web/src/App.tsx", import.meta.url));
const MAX_GAP = 24;

const browser = await chromium.launch();
async function signIn(ctx) {
  const page = await ctx.newPage();
  await page.goto(base + "/login");
  await page.fill("#login-email", email);
  await page.fill("#login-password", password);
  await page.click('form[aria-labelledby="login-title"] button[type=submit]');
  await page.locator("nav[aria-label=Main]").waitFor({ state: "attached", timeout: 20000 });
  return page;
}

const probe = await signIn(await browser.newContext());
const get = async (p) => (await probe.request.get(base + "/api/v1" + p)).json();
const routes = ["/"];
const skipped = [];
for (const p of appRoutes(app)) {
  const r = await fillParams(p, get);
  if (r) routes.push(r);
  else skipped.push(p);
}

const failures = [];
for (const [w, h] of WIDTHS) {
  const ctx = await browser.newContext({ viewport: { width: w, height: h }, ...(w < 500 ? { isMobile: true, hasTouch: true } : {}) });
  const page = await signIn(ctx);
  for (const r of routes) {
    await page.goto(base + r);
    await page.waitForLoadState("networkidle").catch(() => {});
    await page.waitForTimeout(300);
    const m = await page.evaluate(() => {
      const doc = document.documentElement.scrollHeight;
      window.scrollTo(0, doc);
      const sb = document.querySelector(".sidebar");
      const sbRect = sb && getComputedStyle(sb).display !== "none" ? sb.getBoundingClientRect() : null;
      let last = 0;
      for (const el of document.querySelectorAll("#main *, .topbar")) {
        const cs = getComputedStyle(el);
        if (cs.position === "fixed" || cs.display === "none" || cs.visibility === "hidden") continue;
        const rect = el.getBoundingClientRect();
        if (rect.height === 0 || rect.width === 0 || el.closest(".sr-only")) continue;
        last = Math.max(last, rect.bottom + scrollY);
      }
      const main = document.querySelector("#main");
      const pad = main ? parseFloat(getComputedStyle(main).paddingBottom) : 0;
      return {
        doc,
        vh: innerHeight,
        sbTop: sbRect ? Math.round(sbRect.top) : null,
        sbBottom: sbRect ? Math.round(sbRect.bottom) : null,
        last: Math.round(last),
        pad,
        wide: document.documentElement.scrollWidth - innerWidth,
      };
    });
    const problems = [];
    if (m.sbTop !== null && (m.sbTop > 1 || m.sbBottom < m.vh - 1))
      problems.push(`sidebar covers ${m.sbTop}..${m.sbBottom} px of a ${m.vh} px screen when scrolled to the bottom`);
    const gap = m.doc <= m.vh ? 0 : m.doc - m.last - m.pad;
    if (gap > MAX_GAP) problems.push(`${Math.round(gap)} px empty below the last element`);
    for (const [prefix, widths, checks] of EXTRA_CHECKS) {
      if (!widths.includes(w) || !(prefix === "/" ? true : r === prefix || r.startsWith(prefix + "/"))) continue;
      if (checks.includes("no-horizontal-scroll") && m.wide > 0) problems.push(`${m.wide} px wider than the screen (horizontal scroll)`);
    }
    if (problems.length) failures.push(`${w}px ${r}: ${problems.join("; ")}`);
  }
  await ctx.close();
}
await browser.close();

console.log(`layout: ${routes.length} routes at ${WIDTHS.map(([w]) => w).join(" and ")} px`);
if (skipped.length) console.log(`skipped (no value for their parameter): ${skipped.join(", ")}`);
if (failures.length) {
  console.error(`\nLAYOUT CHECK FAILED on ${failures.length}:\n  ${failures.join("\n  ")}`);
  process.exit(1);
}
console.log("layout: passed");
