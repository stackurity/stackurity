/**
 * The questions Ask Stackurity offers before the first one is typed: what
 * needs doing now (about the page open when it is an issue, asset, package
 * or fix), and how to set something up. One click asks it, so the quickest
 * way to start is to ask (owner, 21 Nov 2026). Plain data: node --test
 * loads it.
 */

export interface Starters {
  /** About the estate: what to look at first. */
  now: string[];
  /** About using Stackurity: how to set something up. */
  how: string[];
}

export interface StarterOptions {
  /** May add servers, invite people and connect integrations (organisation admin). */
  admin: boolean;
}

/** Questions about the page open, when it has a subject Ask can read. */
const ABOUT_PAGE: [RegExp, string][] = [
  [/^\/assets\/\d+$/, "What should I fix on this asset first?"],
  [/^\/findings\/\d+$/, "How do I fix this issue, and how urgent is it?"],
  [/^\/components\/\d+$/, "Where is this package installed, and which versions are vulnerable?"],
  [/^\/fixes\/(?!issues$|automatic$|leaks$|config$|code$|mine$)[^/]+$/, "What does this fix change, and is it safe to apply?"],
];

/** Questions for list pages, in the words of someone looking at them. */
const ON_PAGE: [RegExp, string][] = [
  [/^\/fixes\/leaks/, "Which leaked keys should we rotate first?"],
  [/^\/fixes\/config/, "Which risky settings matter most here?"],
  [/^\/fixes\/code/, "Which code findings are real risks?"],
  [/^\/(fixes|action-plan)(\/|$)/, "Which fix removes the most risk?"],
  [/^\/incidents/, "What is happening right now, and what should I do?"],
  [/^\/coverage/, "What isn't Stackurity checking yet?"],
  [/^\/components/, "Which packages are end-of-life?"],
  [/^\/assets/, "Which internet-facing servers have critical issues?"],
  [/^\/reports/, "What will an auditor ask about our open issues?"],
];

const NOW = ["What needs immediate attention?", "What's most important to fix this week?", "Was anything fixed since yesterday?"];

/** The starters for a page: at most three of each kind, the page's own first. */
export function startersFor(pathname: string, o: StarterOptions): Starters {
  const page = ABOUT_PAGE.find(([re]) => re.test(pathname))?.[1] ?? ON_PAGE.find(([re]) => re.test(pathname))?.[1];
  const now = [...(page ? [page] : []), ...NOW].slice(0, 3);
  const how = [
    ...(pathname.startsWith("/integrations") ? ["Which integrations should I connect first?"] : []),
    ...(o.admin ? ["How do I add a server?", "How do I invite my team?"] : []),
    "How do I get alerts in Slack or Teams?",
    "How do I use Stackurity day to day?",
  ].slice(0, 3);
  return { now, how };
}
