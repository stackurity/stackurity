// Renders "How to fix" for a group of issues with no fixed version, as the
// fix page shows it: Vite compiles the .tsx (node --test cannot) and
// react-dom/server renders it inside a router. The advice is what the server
// returns for a Ghost install (test data).
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";
import type { NoFixAdvice } from "./api.ts";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let View: ComponentType<any>;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let Settings: Record<string, any>;

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  View = ((await vite.ssrLoadModule("/src/components/NoFixAdvice.tsx")) as { NoFixAdviceView: ComponentType<unknown> }).NoFixAdviceView;
  Settings = await vite.ssrLoadModule("/src/pages/settings/UnmaintainedCard.tsx");
});
after(async () => {
  await vite?.close();
});

const dir = "/var/www/ghost/versions/6.52.0";
const advice: NoFixAdvice = {
  bundled: {
    app: "ghost",
    app_version: "6.52.0",
    app_dir: dir,
    text: `These packages come with ghost 6.52.0 (${dir}), as part of its dependencies: you can't upgrade them on their own; only a ghost upgrade changes them.`,
    commands: [`cd ${dir} && pnpm why babel-traverse lodash.pick`, `cd ${dir}/content/themes/source && yarn why extract-zip`],
  },
  sections: [
    {
      kind: "renamed",
      title: "Fixed under another name",
      issues: 2,
      items: [
        {
          component: "babel-traverse",
          version: "6.26.0",
          issues: ["CVE-2023-45133"],
          text: "Fixed in @babel/traverse 7.23.2; babel-traverse gets no fix: move to @babel/traverse.",
          move_to: "@babel/traverse",
          fixed_version: "7.23.2",
          bundled: true,
        },
        {
          component: "lodash.pick",
          version: "4.4.0",
          issues: ["CVE-2020-8203"],
          text: "Fixed in lodash 4.17.19; lodash.pick gets no fix: move to lodash.",
          bundled: true,
        },
      ],
    },
    {
      kind: "unmaintained",
      title: "No release for 24 months or more (your risk policy)",
      issues: 1,
      unmaintained_months: 24,
      items: [
        {
          component: "html-minifier",
          version: "4.0.0",
          issues: ["CVE-2022-37620"],
          text: "No release since April 2019 (4.0.0); a fix may not come.",
          last_release: "2019-04-01",
          bundled: true,
        },
      ],
    },
    {
      kind: "no_fix_yet",
      title: "No fix yet",
      issues: 1,
      items: [
        {
          component: "node-forge",
          version: "1.4.0",
          issues: ["CVE-2026-33894"],
          text: "No fixed release yet. GHSA-aaaa-bbbb-cccc gives a workaround.",
          workaround: "Do not verify signatures from <untrusted> sources.",
          workaround_source: "GHSA-aaaa-bbbb-cccc",
          bundled: true,
        },
      ],
    },
  ],
};

function render(a: NoFixAdvice, canEditPolicy = false): string {
  return renderToStaticMarkup(
    h(
      MemoryRouter,
      { initialEntries: ["/fixes/5%3Ano_fix"] },
      h(View, { advice: a, accept: { hash: "#accept" }, snooze: { hash: "#snooze" }, canEditPolicy }),
    ),
  );
}

/** The visible text, tags removed and entities decoded. */
function text(html: string): string {
  return html
    .replace(/<[^>]+>/g, " ")
    .replace(/&#x27;|&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .trim();
}

test("per-package lines grouped by kind, with the bundled note and commands once at the top", () => {
  const html = render(advice);
  const t = text(html);
  assert.ok(t.startsWith("These packages come with ghost 6.52.0"), t);
  assert.ok(t.includes("only a ghost upgrade changes them"));
  assert.ok(t.includes("To see which of ghost's dependencies pulls each one in:"));
  assert.ok(t.includes(`cd ${dir} && pnpm why babel-traverse lodash.pick`));
  assert.ok(t.includes(`cd ${dir}/content/themes/source && yarn why extract-zip`));
  assert.ok(t.includes("Fixed under another name (2 issues)"));
  assert.ok(t.includes("babel-traverse 6.26.0 CVE-2023-45133 Fixed in @babel/traverse 7.23.2; babel-traverse gets no fix: move to @babel/traverse."), t);
  assert.ok(t.includes("No fix yet (1 issue)"));
  // The bundled note comes once, not per package.
  assert.equal(t.split("only a ghost upgrade").length - 1, 1);
  assert.ok(t.indexOf("Fixed under another name") < t.indexOf("No fix yet"), "sections keep the server's order");
});

test("the advisory's workaround is quoted and attributed, never rendered as markup", () => {
  const html = render(advice);
  assert.ok(html.includes("<blockquote"));
  assert.ok(text(html).includes("Workaround, as GHSA-aaaa-bbbb-cccc gives it: Do not verify signatures from <untrusted> sources."));
  assert.ok(!html.includes("<untrusted>"), "advisory text is escaped");
});

test("the decisions link to the fix page's existing forms", () => {
  const html = render(advice);
  const links = [...html.matchAll(/<a href="([^"]*)"[^>]*>([^<]*)<\/a>/g)].map((m) => `${m[2]} -> ${m[1]}`);
  assert.deepEqual(links, [
    "mitigate it with a note -> /fixes/5%3Ano_fix#accept",
    "accept the risk until a date -> /fixes/5%3Ano_fix#accept",
    "ignore it with a reason -> /fixes/5%3Ano_fix#accept",
    "snooze it until a fix is published -> /fixes/5%3Ano_fix#snooze",
  ]);
});

test("without an application, no bundled note or command", () => {
  const t = text(render({ sections: advice.sections }));
  assert.ok(!t.includes("upgrade changes"));
  assert.ok(!t.includes("pnpm why"));
  assert.ok(t.startsWith("Fixed under another name"));
});

test("the unmaintained heading names the risk policy's rule, linked to the setting for admins only", () => {
  assert.ok(text(render(advice)).includes("No release for 24 months or more (your risk policy) (1 issue)"));
  assert.ok(!render(advice).includes("/settings/risk-policy"), "no link for people who cannot change the policy");
  const html = render(advice, true);
  assert.match(html, /<a [^>]*href="\/settings\/risk-policy#unmaintained-months"[^>]*>your risk policy<\/a>/);
  assert.match(text(html), /No release for 24 months or more \( ?your risk policy ?\) \(1 issue\)/);
  // A heading that names no policy rule gets no link.
  const deprecated = { sections: [{ ...advice.sections[1], title: "Deprecated by the maintainers", unmaintained_months: undefined }] };
  assert.ok(!render(deprecated, true).includes("/settings/risk-policy"));
});

test("settings: the unmaintained field shows the policy's months, the default when unset, and flags values out of range", () => {
  const card = (policy: Record<string, unknown>) =>
    renderToStaticMarkup(h(MemoryRouter, null, h(Settings.UnmaintainedCard, { policy, onChange: () => {} })));
  const unset = card({});
  assert.ok(text(unset).includes("Treat a package as unmaintained after (months without a release)"));
  assert.match(unset, /id="unmaintained-months"[^>]*min="6"[^>]*max="120"[^>]*value="24"/);
  assert.ok(text(unset).includes("Between 6 and 120. Default 24."));
  assert.match(card({ unmaintained_months: 36 }), /value="36"/);
  assert.ok(!text(card({ unmaintained_months: 36 })).includes("must be a whole number"));
  assert.ok(text(card({ unmaintained_months: 5 })).includes("must be a whole number between 6 and 120"));
  for (const [n, ok] of [[undefined, true], [6, true], [120, true], [5, false], [121, false], [12.5, false]] as const) {
    assert.equal(Settings.unmaintainedValid({ unmaintained_months: n }), ok, `months ${n}`);
  }
});
