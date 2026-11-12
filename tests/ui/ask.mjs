// Browser checks of Ask Stackurity's panel, at desktop and phone widths,
// against a server whose model provider is tools/fakeclaude:
//   - the panel stays open with the same conversation while the person
//     moves to two other pages, and an answer still streaming finishes;
//   - a half-typed question survives navigation and a reload, and the
//     panel comes back open on the same conversation after a reload;
//   - minimised, the page behind can be used; restored, nothing is lost;
//   - an answer that links a fix shows the fix's stored command with Copy,
//     an issue gets Read more links to advisory sites only, and only the
//     allowed dashboard pages are links;
//   - Chat, History and Feedback are tabs, and Feedback on Ask is a form
//     inside the panel;
//   - a change Ask proposes shows as a card under the answer; Apply makes
//     it (the card says Applied), Undo reverses it, Dismiss leaves it
//     undone, a proposal nobody asked for says so, and History keeps the
//     cards' states;
//   - connection hand-offs: a pasted secret is warned about while typing
//     and removed before the model sees it; a webhook card links to its
//     setup page; a server card creates the install code only on Apply and
//     shows the command with Copy; the GitHub card's button sends the same
//     request, to the same GitHub address, as the Integrations page's
//     Install on GitHub (the redirect is intercepted, never followed), and
//     the panel is open again, the card Started, back on the dashboard;
//   - no console errors and no horizontal scroll.
//
//   node ask.mjs <base url> [email] [password]
//
// With ASK_SHOTS set to a directory, the proposal card's states are saved
// there as propose-<state>-<width>.png, and the hand-off cards as
// handoff-<kind>-<state>-<width>.png. The GitHub button check needs the
// server's GitHub App set up (any test values); without it the card is a
// link, which is checked instead.
import { chromium } from "playwright";

const [base = "http://127.0.0.1:8080", email = "ui@example.com", password = "UI-test-password-1."] = process.argv.slice(2);
const failures = [];
const ok = (cond, what) => {
  console.log(`${cond ? "PASS" : "FAIL"} ${what}`);
  if (!cond) failures.push(what);
};

const shots = process.env.ASK_SHOTS || "";
// The server takes 10 questions a minute per person, in windows aligned to
// the minute: past 9 in this one, wait for the next.
const asked = [];
const pace = async (page) => {
  const minute = Math.floor(Date.now() / 60000);
  if (asked.filter((m) => m === minute).length >= 9) await page.waitForTimeout((minute + 1) * 60000 - Date.now() + 1500);
  asked.push(Math.floor(Date.now() / 60000));
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
  // The demo answer links issue #1, which the demo estate may not have: the
  // panel's look-up of it may 404, which is expected.
  page.on("console", (m) => m.type() === "error" && !/\/api\/v1\/(findings|fix-groups)\//.test(m.location().url ?? "") && errors.push(m.text()));
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
  await pace(page);
  await panel.getByRole("button", { name: "Ask", exact: true }).click();
  await log.getByText("Short answer:").waitFor();
  await panel.getByRole("button", { name: "Ask", exact: true }).waitFor();
  const before = await log.innerText();

  // Command card, Read more and page links. The demo estate has no issues
  // while feeds are off, so the fix group and issue the answer links are
  // served here, as the API would send them.
  const fixId = "9001:security_updates";
  const cmd = "sudo apt update && sudo apt upgrade";
  await page.route(`**/api/v1/fix-groups/${encodeURIComponent(fixId)}?*`, (r) =>
    r.fulfill({ json: { group: { id: fixId, title: "Install security updates", action: cmd, asset_name: "demo-web-1", reboot: true, places: null }, findings: null } }),
  );
  await page.route("**/api/v1/findings/9002", (r) =>
    r.fulfill({
      json: {
        finding: { id: 9002, key: "CVE-2024-3094" },
        advisories: [
          {
            id: "GHSA-6jjj-mmmm-pppp",
            aliases: ["CVE-2024-3094"],
            references: [
              { type: "ADVISORY", url: "https://security-tracker.debian.org/tracker/CVE-2024-3094" },
              { type: "WEB", url: "https://evil.example/pwn" },
              { type: "WEB", url: "http://access.redhat.com/x" },
            ],
          },
        ],
      },
    }),
  );
  await q.fill(`linkfix:${fixId} linkissue:9002`);
  await pace(page);
  await panel.getByRole("button", { name: "Ask", exact: true }).click();
  await log.getByText("Links answer:").waitFor();
  const cmdCard = log.locator(".ask-cmd").last();
  await cmdCard.waitFor();
  ok((await cmdCard.locator("pre").innerText()).trim() === cmd, `${tag} the fix's stored command is shown`);
  ok((await cmdCard.innerText()).includes("Run this on demo-web-1") && (await cmdCard.innerText()).includes("Restart demo-web-1"), `${tag} the card says where to run it and to restart`);
  ok(await cmdCard.getByRole("button", { name: "Copy" }).isVisible(), `${tag} the command has a Copy button`);
  const more = log.locator(".ask-readmore").last();
  await more.locator("summary").click();
  const hrefs = await more.locator("a[target=_blank]").evaluateAll((as) => as.map((a) => [a.href, a.rel]));
  ok(
    hrefs.length === 3 && hrefs.every(([h, rel]) => h.startsWith("https://") && !h.includes("evil") && rel === "noopener noreferrer"),
    `${tag} Read more has only https advisory-site links that open safely ${JSON.stringify(hrefs.map((x) => x[0]))}`,
  );
  const answerLinks = await log.evaluate((el) => [...el.querySelectorAll(".ask-answer a")].map((a) => a.getAttribute("href")));
  ok(answerLinks.includes("/audit") && !answerLinks.includes("/settings/tokens"), `${tag} only allowed pages are links`);
  await page.unrouteAll();

  // An answer still streaming survives moving to another page.
  await q.fill("slow answer please");
  await pace(page);
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

  // Chat, History and Feedback are tabs: the one shown is selected. Feedback
  // on Ask is a form inside the panel, never a dialog over the page.
  const tab = (name) => panel.getByRole("tab", { name });
  ok((await tab("Chat").getAttribute("aria-selected")) === "true", `${tag} the Chat tab is selected in a chat`);
  await tab(/^History/).click();
  ok((await tab(/^History/).getAttribute("aria-selected")) === "true", `${tag} the History tab is selected when shown`);
  ok(await panel.locator(".ask-history-current").isVisible(), `${tag} History marks the open conversation`);
  await tab("Feedback").click();
  ok(await panel.getByRole("heading", { name: "Feedback on Ask" }).isVisible(), `${tag} Feedback opens inside the panel`);
  ok((await page.locator('[role=dialog][aria-modal="true"]').count()) === 0, `${tag} Feedback on Ask is not a dialog over the page`);
  await panel.getByRole("button", { name: "Cancel" }).click();
  ok((await tab("Chat").getAttribute("aria-selected")) === "true", `${tag} Cancel goes back to the chat`);

  const w = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  ok(w <= 1, `${tag} no horizontal scroll (${w}px)`);

  // Proposed changes: Ask proposes, only the click applies.
  const set = await api("PUT", "/ask/settings", JSON.stringify({ propose_changes: true }));
  ok(set.status() === 200, `${tag} "Ask may propose changes" turned on (${set.status()})`);
  const run = Date.now() % 100000; // a rerun against the same database needs new names
  const name = `UI proposals ${width} ${run}`;
  const made = await api("POST", "/projects", JSON.stringify({ name }));
  const project = (await made.json()).id;
  ok(made.status() === 201 || made.status() === 200, `${tag} project created (${made.status()})`);
  const projectName = async () => (await (await api("GET", `/projects/${project}`)).json()).project?.name;
  const shot = async (state) => {
    if (shots) await panel.screenshot({ path: `${shots}/propose-${state}-${width}.png` });
  };
  const ask = async (question) => {
    await q.fill(question);
    await pace(page);
    await panel.getByRole("button", { name: "Ask", exact: true }).click();
    await panel.getByRole("button", { name: "Ask", exact: true }).waitFor();
  };
  const noScroll = async (what) => {
    const sw = await page.evaluate(() => {
      const log = document.querySelector(".ask-log");
      return Math.max(document.documentElement.scrollWidth - document.documentElement.clientWidth, log ? log.scrollWidth - log.clientWidth : 0);
    });
    ok(sw <= 1, `${tag} ${what}: no horizontal scroll (${sw}px)`);
  };
  await panel.getByRole("button", { name: "New chat" }).click();
  await ask(`rename project ${project} to UI renamed ${width} ${run}`);
  const card = log.locator(".ask-proposal").last();
  await card.waitFor();
  ok((await card.innerText()).includes(`Rename the project "${name}"`), `${tag} the card says what will change`);
  ok((await card.getByText("Nothing changes until you click Apply.").count()) === 0, `${tag} the card does not repeat the line under the answer`);
  ok((await log.locator(".ask-ran-note").last().innerText()).includes("Nothing changes until you click Apply."), `${tag} the line under the answer says so too`);
  ok(!(await card.innerText()).includes("you didn't ask"), `${tag} a requested change has no "you didn't ask" note`);
  ok((await projectName()) === name, `${tag} proposing changed nothing`);
  await noScroll("proposed card");
  await shot("proposed");
  await card.getByRole("button", { name: "Apply" }).click();
  await card.getByText(/^Applied at /).waitFor();
  ok(await card.locator(".badge", { hasText: "Applied" }).isVisible(), `${tag} Apply: the card says Applied`);
  ok((await card.getByRole("link", { name: "View what changed" }).getAttribute("href")) === `/projects/${project}`, `${tag} Applied links to the project`);
  ok((await projectName()) === `UI renamed ${width} ${run}`, `${tag} Apply renamed the project`);
  await noScroll("applied card");
  await shot("applied");
  await card.getByRole("button", { name: "Undo" }).click();
  await card.locator(".badge", { hasText: "Undone" }).waitFor();
  ok((await projectName()) === name, `${tag} Undo put the old name back`);
  await shot("undone");

  await ask(`rename project ${project} to UI dismissed ${width} ${run}`);
  const second = log.locator(".ask-proposal").last();
  await second.getByRole("button", { name: "Dismiss" }).click();
  await second.locator(".badge", { hasText: "Dismissed" }).waitFor();
  ok((await projectName()) === name, `${tag} Dismiss changed nothing`);
  ok((await second.getByRole("button").count()) === 0, `${tag} a dismissed card has no buttons`);
  await shot("dismissed");

  await ask(`what is project ${project}`);
  const third = log.locator(".ask-proposal").last();
  await third.waitFor();
  ok(await third.getByText("Ask suggested this; you didn't ask for a change.").isVisible(), `${tag} an unasked proposal says so`);
  await noScroll("unasked card");
  await shot("unasked");
  await third.getByRole("button", { name: "Dismiss" }).click();
  await third.locator(".badge", { hasText: "Dismissed" }).waitFor();

  // History keeps the cards' states.
  await panel.getByRole("tab", { name: /^History/ }).click();
  await panel.locator(".ask-history-open").first().click();
  await log.locator(".ask-proposal").first().waitFor();
  const states = await log.locator(".ask-proposal .badge").allInnerTexts();
  ok(JSON.stringify(states) === JSON.stringify(["Undone", "Dismissed", "Dismissed"]), `${tag} History keeps the card states ${JSON.stringify(states)}`);
  // Closed, it stays closed after a reload.
  await panel.getByRole("button", { name: "Close" }).click();
  await page.reload();
  await page.locator("nav[aria-label=Main]").waitFor({ state: "attached" });
  ok(!(await panel.isVisible()), `${tag} closed stays closed after a reload`);

  // Hand-offs: Ask starts a connection; the person finishes it.
  const hshot = async (state) => {
    if (shots) await panel.screenshot({ path: `${shots}/handoff-${state}-${width}.png` });
  };
  await page.locator("button.topbar-ask").click();
  await panel.waitFor();
  await panel.getByRole("button", { name: "New chat" }).click();
  // A pasted secret: warned while typing, removed before it is kept or
  // sent. A webhook: a link to its setup page, nothing secret in it.
  const secret = "https://hooks.slack.com/services/T0000000/B0000000/abcdefghijklmnopqrstuvwx";
  await q.fill(`connect our webhook, the address is ${secret}`);
  ok(await panel.locator(".ask-secret-warning").isVisible(), `${tag} typing a secret shows a warning`);
  await hshot("secret-typing");
  await ask(`connect our webhook, the address is ${secret}`);
  await log.getByText(/removed what looked like a secret/).waitFor();
  const said = await log.innerText();
  ok(said.includes("(secret removed)") && !said.includes("hooks.slack.com"), `${tag} the question is shown without the secret`);
  const wh = log.locator(".ask-handoff").last();
  await wh.waitFor();
  const whLink = wh.getByRole("link", { name: "Open Webhook setup" });
  ok((await whLink.getAttribute("href")) === "/integrations/new/webhook", `${tag} the webhook card links to its setup page`);
  ok((await log.locator(".ask-ran-note").last().innerText()).includes("Nothing is connected until you finish"), `${tag} the line under the answer says nothing is connected`);
  await noScroll("webhook card");
  await hshot("secret-removed-webhook");

  // A server: Apply creates the install code, as the person; the card shows
  // the command with Copy.
  const label = `ui-web-${width}-${run}`;
  const codes = async () => ((await (await api("GET", "/enrollments")).json()).items ?? []).filter((e) => e.label === label).length;
  await ask(`add a new server called ${label}`);
  const sv = log.locator(".ask-handoff").last();
  await sv.waitFor();
  ok((await sv.innerText()).includes(`label "${label}"`), `${tag} the server card says what will be created`);
  ok((await sv.locator(".codeblock").count()) === 0 && (await codes()) === 0, `${tag} no install code before Apply`);
  await noScroll("server card");
  await hshot("server-proposed");
  await sv.getByRole("button", { name: "Apply" }).click();
  await sv.locator(".codeblock pre").first().waitFor();
  const installCmd = await sv.locator(".codeblock pre").first().innerText();
  ok(installCmd.startsWith("curl -fsSL ") && installCmd.includes("STACKURITY_ENROLL_CODE="), `${tag} Apply shows the install command`);
  ok(await sv.getByRole("button", { name: /^Copy/ }).isVisible(), `${tag} the command has Copy`);
  ok((await sv.locator("textarea, input[type=text]").count()) === 0, `${tag} the command is copy-only`);
  ok(await sv.locator(".badge", { hasText: "Code created" }).isVisible(), `${tag} the card says Code created`);
  ok((await codes()) === 1, `${tag} Apply created one install code`);
  await noScroll("server card with the command");
  if (shots) await sv.screenshot({ path: `${shots}/handoff-server-command-${width}.png` });
  await hshot("server-applied");

  // GitHub: the card's button and the Integrations page's Install on GitHub
  // make the same request and go to the same GitHub address. The redirect
  // is intercepted, never followed.
  const ghPosts = [];
  const ghNav = [];
  page.on("request", (r) => {
    if (r.url().endsWith("/api/v1/integrations/github/install")) ghPosts.push(r.postData());
  });
  await page.route("https://github.com/**", (route) => {
    ghNav.push(route.request().url());
    return route.fulfill({ status: 200, contentType: "text/html", body: "<!doctype html><title>GitHub stub</title><p>Not followed.</p>" });
  });
  await ask("connect our github");
  const gh = log.locator(".ask-handoff").last();
  await gh.locator(".ask-proposal-actions .btn-primary:not([disabled])").waitFor();
  await noScroll("GitHub card");
  await hshot("github-proposed");
  const ghButton = gh.getByRole("button", { name: "Install on GitHub" });
  if ((await ghButton.count()) === 1) {
    await Promise.all([page.waitForURL(/^https:\/\/github\.com\/apps\//), ghButton.click()]);
    const cardPost = ghPosts.at(-1);
    const cardURL = ghNav.at(-1);
    // Back on the dashboard, as GitHub's callback would bring the person.
    await page.goto(base + "/integrations");
    await panel.waitFor();
    const back = log.locator(".ask-handoff").last();
    await back.locator(".badge", { hasText: "Started" }).waitFor();
    ok(true, `${tag} back from GitHub: the panel is open and the card says Started`);
    ok((await back.getByRole("link", { name: "Open the GitHub page" }).getAttribute("href")) === "/integrations", `${tag} Started links to Integrations`);
    await noScroll("started card");
    await hshot("github-started");
    await panel.getByRole("button", { name: "Close" }).click();
    await Promise.all([page.waitForURL(/^https:\/\/github\.com\/apps\//), page.locator("main").getByRole("button", { name: "Install on GitHub" }).click()]);
    const pagePost = ghPosts.at(-1);
    const pageURL = ghNav.at(-1);
    const strip = (u) => {
      const x = new URL(u);
      x.searchParams.delete("state");
      return x.toString();
    };
    ok(ghPosts.length === 2 && cardPost === pagePost, `${tag} the card and the Integrations page send the same request ${cardPost} / ${pagePost}`);
    ok(
      !!cardURL && strip(cardURL) === strip(pageURL) && !!new URL(cardURL).searchParams.get("state") && new URL(cardURL).searchParams.get("state") !== new URL(pageURL).searchParams.get("state"),
      `${tag} both go to the same GitHub address, each with its own state (${cardURL ? strip(cardURL) : "none"})`,
    );
    await page.goto(base + "/integrations");
    await page.locator("nav[aria-label=Main]").waitFor({ state: "attached" });
  } else {
    const href = await gh.getByRole("link", { name: "Open Git repository setup" }).getAttribute("href");
    ok(href === "/integrations/sources?add=git", `${tag} without a GitHub App the card links to the Git repository setup`);
    console.log(`SKIP ${tag} GitHub button: the server has no GitHub App set up (STACKURITY_GITHUB_APP_*)`);
  }
  ok(errors.length === 0, `${tag} no console errors ${errors.slice(0, 2).join(" | ")}`);
  await ctx.close();
}
await browser.close();
if (failures.length) {
  console.error(`${failures.length} Ask check(s) failed`);
  process.exit(1);
}
console.log("Ask checks: all passed");
