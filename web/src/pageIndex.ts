/**
 * Pages, settings and help articles the top search finds by name, so nobody
 * has to hunt through the sidebar for "where do I turn on SSO". Built from
 * the same lists the sidebar, the tab bars and Settings show (navModel.ts),
 * so a page the person may not open is never offered. Plain data, no React:
 * node --test loads it.
 */
import { groupLabel, isAllowed, NAV_GROUPS, SETTINGS_GROUPS, TABS, type Access, type AccessRule } from "./navModel.ts";

export interface PageEntry extends AccessRule {
  to: string;
  title: string;
  /** Where it lives, as the sidebar names it ("Administration › Integrations", "Settings › Plan and usage"). */
  where: string;
  /** Other words people use for it. */
  keywords?: string;
}

/** A help article as the index needs it (help/types.ts Article). */
export interface HelpEntry {
  id: string;
  title: string;
  summary: string;
  keywords?: string;
  where?: string[];
}

export interface PageHit {
  key: string;
  to: string;
  title: string;
  /** "Settings", "Integrations", "Help" … */
  where: string;
  kind: "page" | "help";
}

/** Words people search for that the page's own name does not contain. */
export const KEYWORDS: Record<string, string> = {
  "/": "home overview dashboard summary",
  "/fixes": "to do what to fix upgrades patch priorities action plan my work",
  "/fixes/issues": "findings vulnerabilities cve issues list filter",
  "/fixes/leaks": "secrets keys tokens passwords leaked credentials",
  "/fixes/config": "risky settings ssh agent hooks github actions misconfiguration",
  "/fixes/code": "sast sarif deepsec code scanning",
  "/fixes/automatic": "remediation auto fix automatic upgrades plans",
  "/assets": "servers hosts machines repositories images inventory",
  "/assets/add": "add server install agent linux windows macos enrol new host",
  "/components": "packages libraries software versions sbom",
  "/coverage": "what is checked gaps missing scanned",
  "/intelligence": "feeds advisories osv nvd kev data sources",
  "/components/updates": "outdated new versions end of life eol",
  "/projects": "groups environments teams scope",
  "/project-notifications": "alerts per project",
  "/assets/conflicts": "duplicates same machine merge",
  "/incidents": "sos alerts outages",
  "/checks": "hourly checks runs scans",
  "/approvals": "ignore requests exceptions decisions",
  "/outcomes": "remediation outcomes mttr metrics",
  "/reports": "evidence pack soc 2 iso 27001 pci cra compliance audit export pdf",
  "/audit": "activity log history who changed",
  "/website-check": "website scan domain headers javascript libraries jquery tls outside external",
  "/integrations": "connect github gitlab jira slack teams pagerduty aws azure gcp kubernetes webhook email",
  "/integrations/deliveries": "notifications sent webhook log failed",
  "/integrations/secrets": "credentials stored keys",
  "/integrations/tokens": "api keys tokens ci",
  "/integrations/ai-assistants": "ask stackurity ai claude chatgpt cursor mcp assistant turn on ask",
  "/integrations/plugins": "cloud plugins extensions",
  "/integrations/kubernetes/add": "add cluster k8s helm",
  "/people": "users members invite add user roles admin remove",
  "/people/teams": "teams groups owners",
  "/people/owners": "owner rules assign automatically routing",
  "/settings/risk-policy": "severity priority sla due dates",
  "/settings/fix-grouping": "group fixes upgrades",
  "/settings/vex": "not affected statements openvex",
  "/settings/automatic-fixes": "remediation policies auto upgrade",
  "/settings/project-permissions": "project admins chat apps",
  "/settings/usage": "limits plan usage assets questions",
  "/settings/billing": "plan subscription invoice payment upgrade pricing add-on",
  "/settings/trust-badge": "badge monitored public",
  "/settings/sso": "sso single sign-on saml oidc okta google azure ad login",
  "/settings/jobs": "background jobs queue",
  "/account": "profile password two-factor 2fa mfa passkey email notifications my account",
  "/account#slack": "slack personal notifications dm",
  "/admin/workspaces": "organisations tenants",
  "/admin/health": "status server platform",
  "/admin/license": "license key",
  "/updates": "release notes changelog new",
};

/** Pages outside the tab bars and Settings. */
const EXTRA: PageEntry[] = [
  { to: "/", title: "Dashboard", where: "Overview" },
  { to: "/assets/add", title: "Add a server", where: "Environment › Assets", min: "admin" },
  { to: "/integrations/kubernetes/add", title: "Add a Kubernetes cluster", where: "Administration › Integrations", min: "admin" },
  { to: "/account", title: "Your account", where: "Account" },
  { to: "/account#slack", title: "Slack messages to you", where: "Your account" },
  { to: "/help", title: "Help", where: "Help" },
];

/** Every page with a name, once, with who may open it. */
export const PAGES: PageEntry[] = (() => {
  const out: PageEntry[] = [...EXTRA];
  // A tab's place is its sidebar group, then its tab bar unless the tab is the bar's own page.
  // Items the sidebar shows under their own name (Leaked keys, Incidents), not a whole place (People).
  const inSidebar = new Set(NAV_GROUPS.flatMap((g) => g.items.flatMap((i) => i.links.map((l) => `${l.to}|${i.label}`))));
  const placeOf = (to: string, bar: string, title: string) => {
    const g = groupLabel(to.split("?")[0]);
    if (title === bar || (g && inSidebar.has(`${to}|${title}`))) return g || bar;
    return g ? `${g} › ${bar}` : bar;
  };
  for (const s of Object.values(TABS)) {
    for (const t of s.tabs) {
      const { match: _match, label, ...rule } = t;
      out.push({ ...rule, title: label, where: placeOf(t.to, s.label, label) });
    }
  }
  for (const g of SETTINGS_GROUPS) for (const e of g.entries) out.push({ ...e, title: e.label, where: `Settings › ${g.title}` });
  const seen = new Set<string>();
  return out
    .filter((p) => (seen.has(p.to) ? false : (seen.add(p.to), true)))
    .map((p) => ({ ...p, keywords: KEYWORDS[p.to] ?? p.keywords }));
})();

const words = (s: string) => s.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);

/**
 * How well q matches: 0 the title starts with it, 1 every word starts a
 * title word, 2 every word starts a word of the title, place or keywords;
 * -1 no match.
 */
export function matchRank(q: string, title: string, other: string): number {
  const qw = words(q);
  if (qw.length === 0) return -1;
  const t = title.toLowerCase();
  if (t.startsWith(q.trim().toLowerCase())) return 0;
  const tw = words(title);
  if (qw.every((w) => tw.some((x) => x.startsWith(w)))) return 1;
  const all = [...tw, ...words(other)];
  return qw.every((w) => all.some((x) => x.startsWith(w))) ? 2 : -1;
}

/**
 * The pages, then the help articles, that match q and that this person may
 * open: best match first, at most limit of each.
 */
export function searchPages(q: string, a: Access, help: HelpEntry[] = [], limit = 5): PageHit[] {
  if (q.trim().length < 2) return [];
  const pages = PAGES.filter((p) => isAllowed(p, a))
    .map((p) => ({ p, r: matchRank(q, p.title, `${p.where} ${p.keywords ?? ""}`) }))
    .filter((x) => x.r >= 0)
    .sort((x, y) => x.r - y.r)
    .slice(0, limit)
    .map(({ p }): PageHit => ({ key: `p:${p.to}`, to: p.to, title: p.title, where: p.where, kind: "page" }));
  const articles = help
    .map((h) => ({ h, r: matchRank(q, h.title, `${h.summary} ${h.keywords ?? ""} ${(h.where ?? []).join(" ")}`) }))
    .filter((x) => x.r >= 0)
    .sort((x, y) => x.r - y.r)
    .slice(0, Math.max(1, Math.floor(limit / 2)))
    .map(({ h }): PageHit => ({ key: `h:${h.id}`, to: `/help/${h.id}`, title: h.title, where: "Help", kind: "help" }));
  return [...pages, ...articles];
}
