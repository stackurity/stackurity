// The password rules and a strength estimate for the fields that set a
// password (components/PasswordStrength.tsx).
//
// The rules are the server's (internal/auth/password.go, ValidPassword):
// 12 to 256 characters with at least one lowercase letter, one uppercase
// letter, one digit and one symbol. Letters of any script count by their
// case; a letter without case is a letter, not a symbol; spaces, combining
// marks and control characters are not symbols. The server decides: this
// copy only lets the form say what is missing before it is sent.
//
// The strength is an estimate made here, never sent anywhere: length and
// variety of characters, less what an attacker tries first (repeated
// characters, runs such as abc or 123, common words, and the person's own
// email, name or organisation).

export const MIN_PASSWORD_LENGTH = 12;
export const MAX_PASSWORD_LENGTH = 256;

export type PasswordRule = "length" | "lowercase" | "uppercase" | "digit" | "symbol";

export const RULE_LABELS: Record<PasswordRule, string> = {
  length: `At least ${MIN_PASSWORD_LENGTH} characters`,
  lowercase: "A lowercase letter",
  uppercase: "An uppercase letter",
  digit: "A digit",
  symbol: "A symbol, such as ! # % or -",
};

export const RULES: PasswordRule[] = ["length", "lowercase", "uppercase", "digit", "symbol"];

const LOWER = /\p{Ll}/u;
const UPPER = /\p{Lu}/u;
const LETTER = /\p{L}/u;
const DIGIT = /\p{Nd}/u;
const NOT_SYMBOL = /[\p{M}\p{Cc}\s]/u;

/** Which rules pw meets. */
export function passwordRules(pw: string): Record<PasswordRule, boolean> {
  const chars = [...pw];
  let lowercase = false;
  let uppercase = false;
  let digit = false;
  let symbol = false;
  for (const c of chars) {
    if (LOWER.test(c)) lowercase = true;
    else if (UPPER.test(c)) uppercase = true;
    else if (LETTER.test(c)) continue;
    else if (DIGIT.test(c)) digit = true;
    else if (!NOT_SYMBOL.test(c)) symbol = true;
  }
  return {
    length: chars.length >= MIN_PASSWORD_LENGTH && chars.length <= MAX_PASSWORD_LENGTH,
    lowercase,
    uppercase,
    digit,
    symbol,
  };
}

/** Whether pw meets every rule, so the form may be sent. */
export function passwordOK(pw: string): boolean {
  const r = passwordRules(pw);
  return RULES.every((k) => r[k]);
}

export type Strength = "weak" | "fair" | "strong";

export const STRENGTH_LABELS: Record<Strength, string> = { weak: "Weak", fair: "Fair", strong: "Strong" };

// What attackers try first. Matched in lowercase, with common letter-for-
// digit swaps undone (p4ssw0rd is password).
const COMMON = [
  "password",
  "passwort",
  "stackurity",
  "qwerty",
  "qwertz",
  "azerty",
  "asdf",
  "zxcv",
  "letmein",
  "welcome",
  "admin",
  "login",
  "secret",
  "iloveyou",
  "monkey",
  "dragon",
  "master",
  "sunshine",
  "football",
  "baseball",
  "changeme",
  "trustno",
  "hello",
];

const LEET: Record<string, string> = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", $: "s", "!": "i" };

/** Words of the person's own details worth matching: email, name, organisation. */
export function contextWords(...details: (string | undefined)[]): string[] {
  const out = new Set<string>();
  for (const d of details) {
    for (const w of (d ?? "").toLowerCase().split(/[^\p{L}\p{Nd}]+/u)) if ([...w].length >= 3) out.add(w);
  }
  return [...out];
}

export interface StrengthResult {
  strength: Strength;
  /** Characters left after what attackers try first is discounted. */
  effective: number;
  /** An estimate of the guesses needed, in bits. */
  bits: number;
}

/**
 * The strength of pw. Weak while a rule is missing; Strong when every rule
 * is met and at least 16 characters remain after discounting patterns, or
 * the estimate is high (90 bits, about 14 random characters).
 */
export function passwordStrength(pw: string, context: string[] = []): StrengthResult {
  const chars = [...pw];
  if (chars.length === 0) return { strength: "weak", effective: 0, bits: 0 };
  // Each character counts once, except one that repeats or continues a
  // pattern: those count nothing beyond the pattern's first character.
  const weight = chars.map(() => 1);
  const discount = (from: number, len: number) => {
    for (let i = from + 1; i < from + len; i++) weight[i] = 0;
  };
  // Runs of the same character (aaa) and sequences (abc, 321).
  let i = 0;
  while (i < chars.length - 1) {
    const step = chars[i + 1].codePointAt(0)! - chars[i].codePointAt(0)!;
    if (step < -1 || step > 1) {
      i++;
      continue;
    }
    let j = i + 1;
    while (j + 1 < chars.length && chars[j + 1].codePointAt(0)! - chars[j].codePointAt(0)! === step) j++;
    if (j - i + 1 >= 3) discount(i, j - i + 1);
    i = j;
  }
  // Common words and the person's own details.
  const lower = chars.map((c) => c.toLowerCase());
  const plain = lower.map((c) => LEET[c] ?? c).join("");
  const raw = lower.join("");
  for (const w of [...COMMON, ...context]) {
    const len = [...w].length;
    for (const hay of [raw, plain]) {
      let at = hay.indexOf(w);
      while (at >= 0) {
        // indexOf counts UTF-16 units; the arrays count characters.
        const idx = Array.from(hay.slice(0, at)).length;
        discount(idx, len);
        at = hay.indexOf(w, at + w.length);
      }
    }
  }
  const effective = weight.reduce((a, b) => a + b, 0);
  const r = passwordRules(pw);
  let pool = 0;
  if (r.lowercase) pool += 26;
  if (r.uppercase) pool += 26;
  if (r.digit) pool += 10;
  if (r.symbol) pool += 33;
  if (/\s/u.test(pw)) pool += 1;
  if (chars.some((c) => LETTER.test(c) && !LOWER.test(c) && !UPPER.test(c))) pool += 100; // letters without case
  const bits = Math.round(effective * Math.log2(Math.max(pool, 2)));
  let strength: Strength;
  if (!RULES.every((k) => r[k]) || bits < 60) strength = "weak";
  else if (effective >= 16 || bits >= 90) strength = "strong";
  else strength = "fair";
  return { strength, effective, bits };
}
