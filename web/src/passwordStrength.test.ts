import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { contextWords, passwordOK, passwordRules, passwordStrength } from "./passwordStrength.ts";

// The same cases as the server's (internal/auth/password_test.go): the form
// and the server agree on what is missing.
test("the rules match the server's", () => {
  const cases: [string, string[]][] = [
    ["Abcdefgh1!xy", []],
    ["Abcdefg1!xy", ["length"]],
    ["abcdefgh1!xy", ["uppercase"]],
    ["ABCDEFGH1!XY", ["lowercase"]],
    ["Abcdefghi!xy", ["digit"]],
    ["Abcdefghi1xy", ["symbol"]],
    ["short", ["length", "uppercase", "digit", "symbol"]],
    ["", ["length", "lowercase", "uppercase", "digit", "symbol"]],
    ["Correct horse battery 9", ["symbol"]], // a space is not a symbol
    ["émile ÉCOLE 12€", []],
    ["ÄÖÜäöü123456", ["symbol"]],
    ["Ab1密码密码密码密码密码", ["symbol"]], // letters without case are not symbols
    ["Ab1~密码密码密码密码", []],
    ["Abcdefgh1 x😀", []], // 12 characters, one of them an emoji
    ["Abcdefghé1xy", ["symbol"]], // a combining accent is not a symbol
    ["Aé1!éééééé", ["length"]],
    ["Aa1!" + "x".repeat(252), []],
    ["Aa1!" + "x".repeat(253), ["length"]],
  ];
  for (const [pw, missing] of cases) {
    const r = passwordRules(pw);
    assert.deepEqual(
      Object.entries(r)
        .filter(([, ok]) => !ok)
        .map(([k]) => k),
      missing,
      pw,
    );
    assert.equal(passwordOK(pw), missing.length === 0, pw);
  }
});

test("weak, fair and strong", () => {
  const s = (pw: string, ctx: string[] = []) => passwordStrength(pw, ctx).strength;
  // A rule missing: weak, however long.
  assert.equal(s("correct horse battery staple"), "weak");
  assert.equal(s("short"), "weak");
  // Every rule met, but made of what attackers try first.
  assert.equal(s("Password123!"), "weak");
  assert.equal(s("P4ssw0rd!2024"), "weak");
  assert.equal(s("Stackurity2026!"), "weak");
  assert.equal(s("Qwerty!12345"), "weak");
  assert.equal(s("Abcdefgh1!xy"), "weak");
  assert.equal(s("Aaaaaaaaaa1!"), "weak");
  assert.equal(s("Asha.Acme!2026x", contextWords("asha@acme.io", "Asha Rao", "Acme Corp")), "weak");
  // Every rule met, 12 to 15 unpatterned characters: fair.
  assert.equal(s("Tr0ub4dor&3x"), "fair");
  assert.equal(s("Kp9#vLm2qWz!"), "fair");
  // 16 or more characters that are not a pattern, or a high estimate: strong.
  assert.equal(s("Correct horse battery 9!"), "strong");
  assert.equal(s("Kp9#vLm2qWz!rT6&"), "strong");
  assert.equal(s("Velvet-Otter-Lamp-82"), "strong");
  assert.equal(s(""), "weak");
});

test("context words are the person's details, three characters or more", () => {
  assert.deepEqual(contextWords("asha.rao@acme.io", "Asha Rao", undefined, "Acme"), ["asha", "rao", "acme"]);
});

// Every field that sets a password shows the rules, and its form cannot be
// sent until they are met.
function files(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) return files(p);
    return /\.tsx$/.test(n) ? [p] : [];
  });
}

// Fields that take some other service's secret, not an account's password.
const NOT_ACCOUNT_PASSWORDS = ["pages/Onboarding.tsx", "pages/settings/Secrets.tsx"];

test("every new-password field has the checklist, and its form checks passwordOK", () => {
  const src = new URL(".", import.meta.url).pathname;
  const missing: string[] = [];
  let fields = 0;
  for (const f of files(join(src, "pages"))) {
    const text = readFileSync(f, "utf8");
    if (!text.includes('autoComplete="new-password"') || NOT_ACCOUNT_PASSWORDS.includes(f.slice(src.length))) continue;
    fields++;
    if (!text.includes("<PasswordChecklist")) missing.push(`${f.slice(src.length)}: no PasswordChecklist`);
    if (!/disabled=\{[^}]*passwordOK\(/.test(text)) missing.push(`${f.slice(src.length)}: submit not disabled by passwordOK`);
    if (text.includes("At least 12 characters.")) missing.push(`${f.slice(src.length)}: old hint`);
  }
  assert.ok(fields >= 6, `found ${fields} pages with a new-password field`);
  assert.deepEqual(missing, []);
});
