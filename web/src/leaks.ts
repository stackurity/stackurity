// Leaked keys as tracked work: what each state means, and how to rotate
// each kind of key. Kept free of React so node --test can check it.

import type { LeakState, LeakSummary } from "./api";

export const LEAK_STATE: Record<LeakState, { label: string; tone: "bad" | "warn" | "good" | "muted"; hint: string }> = {
  needs_rotation: {
    label: "Needs rotation",
    tone: "bad",
    hint: "Revoke the key where it was issued and replace it with a new one.",
  },
  waiting_check: {
    label: "Rotated, waiting for check",
    tone: "warn",
    hint: "Marked as rotated. The next complete scan that no longer finds the key in the file confirms it.",
  },
  still_found: {
    label: "Still found after rotation",
    tone: "bad",
    hint: "A scan after it was marked as rotated still found the key in the file. Remove it from the file, then check again.",
  },
  verified_gone: {
    label: "Verified gone",
    tone: "good",
    hint: "A complete scan no longer finds the key.",
  },
  dismissed: {
    label: "Dismissed",
    tone: "muted",
    hint: "Kept on purpose, such as a test key. Later scans leave it dismissed.",
  },
};

/** How to rotate one kind of key: short steps and, for big providers, their own guide. */
export interface RotationGuide {
  provider: string;
  steps: string;
  link?: string;
}

const GUIDES: Record<string, RotationGuide> = {
  aws: {
    provider: "AWS",
    steps:
      "In IAM, create a second access key for the same user, put it where the old one was used, then deactivate and delete the old key. CloudTrail shows whether the old key was used by anyone else.",
    link: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
  },
  github: {
    provider: "GitHub",
    steps:
      "Delete the token (Settings → Developer settings → Personal access tokens, or the app's settings for an app or OAuth token) and create a new one with only the access it needs.",
    link: "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
  },
  gitlab: {
    provider: "GitLab",
    steps: "Revoke the token (Preferences → Access tokens, or the project's or group's access tokens) and create a new one.",
    link: "https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html",
  },
  stripe: {
    provider: "Stripe",
    steps: "Roll the key in the Stripe Dashboard (Developers → API keys). Rolling it issues a new key and ends the old one.",
    link: "https://docs.stripe.com/keys",
  },
  slack: {
    provider: "Slack",
    steps: "Regenerate the token or webhook in the app's settings at api.slack.com/apps, and remove the old webhook.",
  },
  privateKey: {
    provider: "Private key",
    steps:
      "Make a new key pair, put the new public key wherever the old one was trusted (authorized_keys, a certificate, a deploy key) and remove the old one there.",
  },
  password: {
    provider: "Password",
    steps: "Change the password at the database or service it opens, then update the configuration that uses it.",
  },
  generic: {
    provider: "Any key",
    steps: "Revoke the key at the service that issued it, issue a new one, and update everything that used the old one.",
  },
};

/** The rotation steps for a leak's rule (internal/collect/leaks rule names). */
export function rotationGuide(rule: string): RotationGuide {
  if (rule.startsWith("aws-")) return GUIDES.aws;
  if (rule.startsWith("github-")) return GUIDES.github;
  if (rule.startsWith("gitlab-")) return GUIDES.gitlab;
  if (rule.startsWith("stripe-")) return GUIDES.stripe;
  if (rule.startsWith("slack-")) return GUIDES.slack;
  if (rule === "private-key") return GUIDES.privateKey;
  if (rule === "database-url" || rule === "password-assignment") return GUIDES.password;
  return GUIDES.generic;
}

/** One line for the dashboard and the Fixes page: what needs doing about leaked keys. */
export function leakWorkLine(s: LeakSummary): string {
  const parts: string[] = [];
  const todo = s.needs_rotation + s.still_found;
  if (todo > 0) parts.push(`${todo} ${todo === 1 ? "needs" : "need"} rotation`);
  if (s.overdue > 0) parts.push(`${s.overdue} overdue`);
  if (s.waiting_check > 0) parts.push(`${s.waiting_check} waiting for a check`);
  return parts.join(", ");
}
