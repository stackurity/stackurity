// Secondary text (muted, small, table headers) and solid buttons meet WCAG AA
// (4.5:1) on every surface they sit on, in the light and the dark theme. The
// tokens are read from styles.css, so changing one that fails is caught here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const css = readFileSync(new URL("./styles.css", import.meta.url), "utf8");

function block(re: RegExp): Record<string, string> {
  const m = css.match(re);
  assert.ok(m, `token block ${re} not found`);
  const out: Record<string, string> = {};
  for (const [, name, value] of m[1].matchAll(/--([a-z0-9-]+):\s*(#[0-9a-f]{6})\s*;/gi)) out[name] = value.toLowerCase();
  return out;
}

const light = block(/^:root \{([\s\S]*?)^\}/m);
// The first dark block holds the theme's tokens.
const dark = { ...light, ...block(/@media \(prefers-color-scheme: dark\) \{\s*:root \{([\s\S]*?)^ {2}\}/m) };

function luminance(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function ratio(a: string, b: string): number {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
}

const SURFACES = ["bg", "surface", "surface-2", "surface-3", "zebra", "row-hover", "accent-soft", "muted-bg"];
const SECONDARY = ["muted", "text-2", "muted-fg", "info-fg", "link", "danger"];

for (const [theme, t] of [
  ["light", light],
  ["dark", dark],
] as const) {
  test(`${theme}: secondary text is at least 4.5:1 on every surface`, () => {
    for (const fg of SECONDARY) {
      for (const bg of SURFACES) {
        assert.ok(t[fg] && t[bg], `${theme} --${fg} or --${bg} missing`);
        const r = ratio(t[fg], t[bg]);
        assert.ok(r >= 4.5, `${theme} --${fg} ${t[fg]} on --${bg} ${t[bg]} is ${r.toFixed(2)}:1`);
      }
    }
  });

  test(`${theme}: badge text is at least 4.5:1 on its own background`, () => {
    for (const tone of ["good", "warn", "bad", "muted", "info"]) {
      const r = ratio(t[`${tone}-fg`], t[`${tone}-bg`]);
      assert.ok(r >= 4.5, `${theme} ${tone} badge is ${r.toFixed(2)}:1`);
    }
  });

  test(`${theme}: white text on primary and destructive buttons is at least 4.5:1`, () => {
    for (const fill of ["accent", "danger-solid"]) {
      const r = ratio("#ffffff", t[fill]);
      assert.ok(r >= 4.5, `${theme} white on --${fill} ${t[fill]} is ${r.toFixed(2)}:1`);
    }
  });
}

test("both themes' tokens were read", () => {
  assert.notEqual(dark.bg, light.bg);
  assert.notEqual(dark.muted, light.muted);
});

test("solid destructive buttons use the solid token, not the text colour", () => {
  assert.match(css, /\.btn-danger \{\s*background: var\(--danger-solid\);/);
});
