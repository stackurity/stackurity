// Browser checks of Ask Stackurity's panel, at desktop and phone widths,
// against a server whose model provider is tools/fakeclaude:
//   - the panel stays open with the same conversation while the person
//     moves to two other pages, and an answer still streaming finishes;
//   - a half-typed question survives navigation and a reload, and the
//     panel comes back open on the same conversation after a reload;
//   - minimised, the page behind can be used; restored, nothing is lost;
//   - no console errors and no horizontal scroll.
//
//   node ask.mjs <base url> [email] [password]
import { chromium } from "playwright";

const [base = "http://127.0.0.1:8080", email = "ui@example.com", password = "UI-test-password-1."] = process.argv.slice(2);
const failures = [];
const ok = (cond, what) => {
  console.log(`${cond ? "PASS" : "FAIL"} ${what}`);
  if (!cond) failures.push(what);
};

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
  // From here on (the login page itself checks for a session first, a 401).
  const errors = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(String(e)));
  const api = (method, path, data) =>
    page.request.fetch(base + "/api/v1" + path, { method, headers: { "X-Stackurity-CSRF": "1", "Content-Type": "application/json" }, data });
  // The admin turns Ask on (a no-op if it already is).
  const consent = await (await api("GET", "/ask/settings")).json();
  const body = consent.consent_version ? { enabled: true, consent_version: consent.consent_version } : { enabled: true };
  const on = await api("PUT", "/ask/settings", JSON.stringify(body));
  ok(on.status() === 200, `${tag} Ask turned on (${on.status()})`);
  // A page navigation inside the app, as a link click does it.
  const go = (path) =>
    page.evaluate((p) => {
      window.history.pushState({}, "", p);
      window.dispatchEvent(new PopStateEvent("popstate"));
    }, path);
  const panel = page.getByRole("dialog", { name: "Ask Stackurity" });
  const log = panel.locator(".ask-log");

  await page.goto(base + "/assets");
  await page.locator("button.topbar-ask").click();
  await panel.waitFor();
  const understand = panel.getByRole("button", { name: "I understand" });
  if (await understand.isVisible()) await understand.click();
  ok(await panel.locator(".ask-avatar").first().isVisible(), `${tag} the panel shows the bot's avatar`);
  // The header's name never runs under its buttons (it did at 390 px).
  const overlap = await panel.locator(".ask-head").evaluate((h) => {
    const who = h.querySelector(".ask-who")?.getBoundingClientRect();
    const btns = [...h.querySelectorAll(".ask-head-actions button")].map((b) => b.getBoundingClientRect());
    const name = h.querySelector(".ask-who strong");
    return {
      clash: Boolean(who && btns.length && who.right > btns[0].left + 1),
      offscreen: btns.some((r) => r.right > window.innerWidth + 1),
      spill: name ? name.scrollWidth > name.clientWidth + 1 && getComputedStyle(name).textOverflow !== "ellipsis" : false,
    };
  });
  ok(!overlap.clash && !overlap.offscreen && !overlap.spill, `${tag} the header's name and buttons don't overlap ${JSON.stringify(overlap)}`);
  const q = panel.getByLabel("Your question");
  await q.fill("What should I fix first?");
  await panel.getByRole("button", { name: "Ask", exact: true }).click();
  await log.getByText("Short answer:").waitFor();
  await panel.getByRole("button", { name: "Ask", exact: true }).waitFor();
  const before = await log.innerText();

  // An answer still streaming survives moving to another page.
  await q.fill("slow answer please");
  await panel.getByRole("button", { name: "Ask", exact: true }).click();
  await panel.getByRole("button", { name: "Stop" }).waitFor();
  if (width < 700) {
    await panel.getByRole("button", { name: "Minimise" }).click();
    ok(await page.locator(".ask-bubble").isVisible(), `${tag} minimised: a small button stays in the corner`);
  }
  await go("/fixes");
  await go("/settings");
  if (width < 700) {
    ok(!(await panel.isVisible()), `${tag} minimised: the page behind is in view`);
    await page.locator(".ask-bubble").click();
  }
  ok(await panel.isVisible(), `${tag} still open after moving to two other pages`);
  await log.getByText("Word299").waitFor({ timeout: 30000 });
  const after = await log.innerText();
  ok(after.startsWith(before.trim().slice(0, 40)) && after.includes("Short answer:"), `${tag} the same conversation is shown`);
  ok(after.includes("Word299"), `${tag} the answer streaming during navigation finished`);

  // A half-typed question survives navigation and a reload; the panel comes
  // back open on the same conversation.
  await q.fill("half typed question");
  if (width < 700) await panel.getByRole("button", { name: "Minimise" }).click();
  await go("/assets");
  if (width < 700) await page.locator(".ask-bubble").click();
  ok((await q.inputValue()) === "half typed question", `${tag} a half-typed question survives navigation`);
  await page.reload();
  await panel.waitFor();
  await log.getByText("Word299").waitFor();
  ok((await log.innerText()).includes("Short answer:"), `${tag} after a reload: open on the same conversation`);
  ok((await panel.getByLabel("Your question").inputValue()) === "half typed question", `${tag} after a reload: the half-typed question is kept`);

  const w = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  ok(w <= 1, `${tag} no horizontal scroll (${w}px)`);
  // Closed, it stays closed after a reload.
  await panel.getByRole("button", { name: "Close" }).click();
  await page.reload();
  await page.locator("nav[aria-label=Main]").waitFor({ state: "attached" });
  ok(!(await panel.isVisible()), `${tag} closed stays closed after a reload`);
  ok(errors.length === 0, `${tag} no console errors ${errors.slice(0, 2).join(" | ")}`);
  await ctx.close();
}
await browser.close();
if (failures.length) {
  console.error(`${failures.length} Ask check(s) failed`);
  process.exit(1);
}
console.log("Ask checks: all passed");
