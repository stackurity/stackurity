// Dashboard pages an Ask Stackurity answer may link to, besides findings,
// assets, components and fix groups (ask.ts ALLOWED). Matched exactly: an
// answer's link to any other path is shown as its text alone. The same list
// is in the system prompt (internal/ask/prompt.go); keep the two in step.
// Plain logic, tested in askRoutes.test.ts.

/** Pages with a fixed address, each a route in App.tsx. */
export const NAV_PATHS: readonly string[] = [
  // Fixes
  "/fixes",
  "/fixes/issues",
  "/fixes/mine",
  "/fixes/leaks",
  "/fixes/config",
  "/fixes/code",
  "/fixes/automatic",
  // Assets
  "/coverage",
  "/components/updates",
  "/projects",
  "/project-notifications",
  // Activity and reports
  "/incidents",
  "/audit",
  "/website-check",
  // Integrations
  "/integrations",
  "/integrations/sources",
  "/integrations/deliveries",
  "/integrations/ai-assistants",
  // People (view only: Ask changes nothing)
  "/people",
  // Settings
  "/settings",
  "/settings/risk-policy",
  "/settings/fix-grouping",
  "/settings/automatic-fixes",
  "/settings/project-permissions",
  "/settings/usage",
  "/settings/jobs",
  "/account",
  "/help",
];

/** Help articles (the ids in help/articles.ts; askRoutes.test.ts checks they match). */
export const HELP_SLUGS: readonly string[] = [
  "getting-started",
  "ai-assistants",
  "what-is-stackurity",
  "daily-workflow",
  "glossary",
  "feedback",
  "add-server",
  "add-many-servers",
  "add-linux-server",
  "ssh-tunnel",
  "windows-hosts",
  "macos-hosts",
  "repositories",
  "gitlab",
  "ci-keyless",
  "github-app",
  "ci-gate",
  "sbom",
  "vex",
  "code-findings",
  "container-images",
  "container-registries",
  "cloud-plugins",
  "google-cloud",
  "azure",
  "kubernetes",
  "action-plan",
  "findings",
  "exceptions",
  "ignore-issues",
  "approvals",
  "check-again",
  "regressed",
  "incidents",
  "asset-reporting",
  "assets",
  "components",
  "updates-available",
  "threat-notices",
  "coverage-intelligence",
  "how-stackurity-knows",
  "evidence-pack",
  "evidence-report",
  "remediation-outcomes",
  "website-check",
  "remediation-overview",
  "remediation-policy",
  "enable-host-remediation",
  "two-factor",
  "risk-policy",
  "notifications",
  "social-sign-in",
  "users-teams-roles",
  "projects",
  "api-tokens",
  "integrations-settings",
  "admin-tools",
  "free-key",
  "owner-rules",
  "backups-upgrades",
];

const FIXED = new Set<string>([...NAV_PATHS, ...HELP_SLUGS.map((s) => `/help/${s}`)]);

// A project's page and its notification rules, by number.
const PROJECT = /^\/projects\/\d{1,18}(?:\/notifications)?$/;

/** True when an answer may link to this dashboard page. */
export function isNavPath(path: string): boolean {
  return FIXED.has(path) || PROJECT.test(path);
}

/**
 * The page where a Help article's task is done. An Ask answer that links
 * the article gets an "Open …" button for it before the article's own
 * (ask.ts pageLinks), so a how-to answer leads to the form, not only to
 * the instructions. These come from here, never from the model's words.
 */
export const HELP_ACTIONS: Readonly<Record<string, { label: string; to: string }>> = {
  "add-server": { label: "Add server", to: "/assets/add" },
  "add-linux-server": { label: "Add server", to: "/assets/add" },
  "windows-hosts": { label: "Add server", to: "/assets/add" },
  "macos-hosts": { label: "Add server", to: "/assets/add" },
  "add-many-servers": { label: "Add many servers", to: "/assets/add?tab=fleet" },
  "two-factor": { label: "Your account", to: "/account" },
  "api-tokens": { label: "API tokens", to: "/integrations/tokens" },
  "users-teams-roles": { label: "Users", to: "/people" },
  projects: { label: "Projects", to: "/projects" },
  "risk-policy": { label: "Risk policy", to: "/settings/risk-policy" },
  "ai-assistants": { label: "AI assistants", to: "/integrations/ai-assistants" },
  "owner-rules": { label: "Owner rules", to: "/people/owners" },
  notifications: { label: "Integrations", to: "/integrations" },
};
