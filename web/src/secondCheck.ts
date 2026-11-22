import type { SecondCheckResult } from "./api";
import type { Tone } from "./components/Badge";

/**
 * How each second check verdict is shown. Confirmed is a neutral fact, not
 * good news (the key is real), so it is not green; fixed is.
 */
export const SECOND_CHECK: Record<SecondCheckResult, { label: string; tone: Tone; hint: string }> = {
  confirmed: {
    label: "Second check: confirmed",
    tone: "info",
    hint: "An independent check agrees: it looks real and was still found at the last scan.",
  },
  likely_false_positive: {
    label: "Second check: likely false positive",
    tone: "muted",
    hint: "An independent check found it is probably not real (a placeholder, a sample, a test key, a test or docs file, or a setting that never takes effect). Listed; only those flagged for their value or setting raise no alert.",
  },
  fixed: {
    label: "Second check: fixed",
    tone: "good",
    hint: "A complete scan no longer finds it.",
  },
  could_not_check: {
    label: "Second check: could not check",
    tone: "warn",
    hint: "The independent check could not read what it needs; the reason says what.",
  },
};

/** The second_check filter for the main list: everything but likely false positives. */
export const NOT_FALSE_POSITIVE = "confirmed,fixed,could_not_check,unchecked";

/** The line under a collapsed list of likely false positives. */
export function falsePositiveSummary(n: number, noun: "leak" | "setting"): string {
  const what = noun === "leak" ? (n === 1 ? "leaked key" : "leaked keys") : n === 1 ? "risky setting" : "risky settings";
  return `${n.toLocaleString()} ${what} the second check found likely false positives`;
}
