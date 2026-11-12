/**
 * Where things are, as the dashboard names them in text ("Integrations ▸ AI
 * assistants", "People, Teams", "Settings → Jobs"), and the page each one
 * opens. Help articles and hints write the path people would click through;
 * placeHref turns it into a link so it is one click away.
 *
 * Keys are lower case with the parts joined by " > ". A path that goes deeper
 * than the table ("People ▸ Users ▸ Invite by email") links its longest known
 * start. Add a row when you name a new place in text.
 */
const PLACES: Record<string, string> = {
  // Fixes
  fixes: "/fixes",
  "fixes > my work": "/fixes/mine",
  "fixes > all issues": "/fixes/issues",
  "fixes > leaked keys": "/fixes/leaks",
  "fixes > automatic fixes": "/fixes/automatic",
  "my work": "/fixes/mine",
  "all issues": "/fixes/issues",
  // Security
  "security > checks": "/checks",
  incidents: "/incidents",
  checks: "/checks",
  // Environment
  assets: "/assets",
  "assets > projects": "/projects",
  "assets > coverage": "/coverage",
  "assets > data sources": "/intelligence",
  "assets > updates available": "/components/updates",
  "assets > identity conflicts": "/assets/conflicts",
  "environment > assets": "/assets",
  "environment > projects": "/projects",
  "environment > coverage": "/coverage",
  components: "/components",
  projects: "/projects",
  coverage: "/coverage",
  "data sources": "/intelligence",
  // Governance
  approvals: "/approvals",
  "governance > approvals": "/approvals",
  "governance > approvals > ignore rules": "/approvals?tab=rules",
  "governance > reports and audit": "/outcomes",
  "governance > reports and audit > audit log": "/audit",
  "reports and audit": "/outcomes",
  "reports > outcomes": "/outcomes",
  "reports > evidence report": "/reports",
  "audit log": "/audit",
  // Administration
  integrations: "/integrations",
  "settings > integrations": "/integrations",
  "integrations > add integration": "/integrations/sources",
  "integrations > container image / registry": "/integrations/sources",
  "integrations > ci pipeline": "/integrations/setup/ci",
  "integrations > slack": "/integrations/new/slack",
  "integrations > delivery log": "/integrations/deliveries",
  "integrations > stored credentials": "/integrations/secrets",
  "integrations > api tokens": "/integrations/tokens",
  "integrations > ai assistants": "/integrations/ai-assistants",
  "integrations > plugins": "/integrations/plugins",
  "administration > integrations": "/integrations",
  people: "/people",
  "people > users": "/people",
  "people > teams": "/people/teams",
  "people > owners": "/people/owners",
  "people > owner rules": "/people/owners",
  "administration > people": "/people",
  // Settings
  settings: "/settings",
  "settings > risk policy": "/settings/risk-policy",
  "settings > fix grouping": "/settings/fix-grouping",
  "settings > vex": "/settings/vex",
  "settings > automatic fixes": "/settings/automatic-fixes",
  "settings > project permissions": "/settings/project-permissions",
  "settings > usage": "/settings/usage",
  "settings > plan and billing": "/settings/billing",
  "settings > single sign-on": "/settings/sso",
  "settings > jobs": "/settings/jobs",
  // Admin and your account
  "admin > licence": "/admin/license",
  "admin > workspaces": "/admin/workspaces",
  "admin > platform health": "/admin/health",
  "your account": "/account",
  "your account > email preferences": "/account#email",
  "your account > two-factor methods": "/account#mfa",
  "your account > sign in with google, microsoft or github": "/account#sign-in",
  "account menu > send feedback": "/feedback",
  // Further pages Help names
  dashboard: "/",
  "automatic fixes": "/fixes/automatic",
  "assets > add server": "/assets/add",
  "components > updates available": "/components/updates",
  "coverage > data sources": "/intelligence",
  "reports and audit > outcomes": "/outcomes",
  "reports and audit > evidence report": "/reports",
  "reports and audit > audit log": "/audit",
  "integrations > aws": "/integrations/aws",
  "integrations > git repository": "/integrations/sources",
  "integrations > kubernetes cluster": "/integrations/kubernetes/add",
  admin: "/admin/workspaces",
};

/** The separators text uses between the parts of a place: ▸, →, > and ", ". */
const SEP = /\s*(?:▸|→|>|,)\s*/;

function key(parts: string[]): string {
  return parts.map((p) => p.trim().toLowerCase()).join(" > ");
}

/**
 * The page a place name opens, or null. Only the whole text is matched
 * (after trimming); a deeper path than the table knows links its longest
 * known start, but only when that start has at least two parts, so "Assets
 * page" or "People in your team" are not mistaken for places.
 */
export function placeHref(text: string): string | null {
  const parts = text.trim().split(SEP).filter(Boolean);
  if (parts.length === 0) return null;
  for (let n = parts.length; n >= 1; n--) {
    if (n === 1 && parts.length > 1) break;
    const to = PLACES[key(parts.slice(0, n))];
    if (to) return to;
  }
  return null;
}

/** Every place of two or more parts, longest first, as a pattern that finds them in running text. */
const MULTI = Object.keys(PLACES)
  .filter((k) => k.includes(" > "))
  .sort((a, b) => b.length - a.length)
  .map((k) =>
    k
      .split(" > ")
      .map((p) => p.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&"))
      .join("\\s*(?:▸|→|>)\\s*"),
  );
const IN_TEXT = new RegExp(`(${MULTI.join("|")})`, "gi");

/**
 * Splits running text into plain strings and places (two or more parts, such
 * as "Integrations → AI assistants") with the page each opens.
 */
export function splitPlaces(text: string): (string | { text: string; to: string })[] {
  const out: (string | { text: string; to: string })[] = [];
  let last = 0;
  for (const m of text.matchAll(IN_TEXT)) {
    const to = placeHref(m[0]);
    if (!to) continue;
    if (m.index > last) out.push(text.slice(last, m.index));
    out.push({ text: m[0], to });
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

/** The sidebar's group headings: a path may start with one ("Administration ▸ People ▸ Users"). */
const GROUPS = new Set(["administration", "environment", "governance", "security"]);

/**
 * The page a Help article's "Where to find it" path opens: its sidebar group
 * left out, then the longest start the table knows, even a single part.
 */
export function whereHref(parts: string[]): string | null {
  const rest = parts.length > 1 && GROUPS.has(parts[0].trim().toLowerCase()) ? parts.slice(1) : parts;
  for (let n = rest.length; n >= 1; n--) {
    const to = PLACES[key(rest.slice(0, n))];
    if (to) return to;
  }
  return null;
}
