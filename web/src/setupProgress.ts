/*
 * The Dashboard's setup checklist (Review 3, point 4D): each step says what
 * doing it gets you, links to the page that does it, and is ticked from what
 * exists in the workspace, so a step done somewhere else counts too.
 * Pure, so it can be tested without a browser.
 */

/**
 * done: what the step needs exists. todo: it does not. unknown: what it
 * reads could not be loaded (never shown as done or as not done).
 */
export type SetupState = "done" | "todo" | "unknown";

/** What the checklist reads; null where it could not be loaded. */
export interface SetupFacts {
  /** GET /onboarding steps. */
  steps: { project: boolean; asset: boolean; notifications: boolean; invite: boolean; assistant: boolean };
  /** GET /overview assets per kind, across every project. */
  assets: Record<string, number> | null;
  /** How many owner rules exist (GET /owner-rules). */
  ownerRules: number | null;
  /** The risk policy was saved at least once (GET /risk-policy last_change). */
  riskPolicySaved: boolean | null;
  /** Automatic fixes are in this workspace's plan. */
  remediationPaid: boolean;
  /** How many automatic-fix policies exist; null when not paid or not loaded. */
  remediationPolicies: number | null;
  /** The signed-in admin has a second factor. */
  mfa: boolean;
}

export interface SetupItem {
  key: string;
  state: SetupState;
  title: string;
  /** Why it is worth doing, in one line. */
  benefit: string;
  /** What you have once it is done. */
  after: string;
  /** The button: its label and the page that does it. */
  action: { label: string; to: string };
  /**
   * Part of the step is in a paid plan this workspace does not have: shown
   * locked, with a link to the page that explains it. It never blocks the tick.
   */
  locked?: { plan: string; text: string; to: string };
}

const count = (n: number | null | undefined): SetupState => (n == null ? "unknown" : n > 0 ? "done" : "todo");
const flag = (b: boolean | null | undefined): SetupState => (b == null ? "unknown" : b ? "done" : "todo");

/** The steps in the order to do them. Creating a project comes first, and only while there is none. */
export function setupItems(f: SetupFacts): SetupItem[] {
  const items: SetupItem[] = [];
  if (!f.steps.project) {
    items.push({
      key: "project",
      state: "todo",
      title: "Create a project",
      benefit: "So servers and repositories are grouped by product, client or team, and people can be given just their part.",
      after: "A place to add your first server or repository.",
      action: { label: "Create a project", to: "/get-started?step=project" },
    });
  }
  const kinds = f.assets;
  items.push(
    {
      key: "server",
      state: kinds ? count(kinds.host ?? 0) : "unknown",
      title: "Connect your first server",
      benefit: "So you know every package your servers run, and which ones have known vulnerabilities, without logging in to each one.",
      after: "Its installed software, issues and fixes, refreshed every 6 hours by a small read-only agent.",
      action: { label: "Add a server", to: "/assets/add" },
    },
    {
      key: "repositories",
      state: kinds ? count(kinds.repository ?? 0) : "unknown",
      title: "Add your source repositories",
      benefit: "So vulnerable libraries are caught in the code, before they reach a server.",
      after: "Each repository's dependencies are checked on every scan, with the version to upgrade to.",
      action: { label: "Add a repository", to: "/integrations/sources" },
    },
    {
      key: "notifications",
      state: flag(f.steps.notifications),
      title: "Turn on vulnerability alerts",
      benefit: "So a new urgent issue reaches you in Slack or email, instead of waiting for someone to open the Dashboard.",
      after: "Urgent issues as they appear, and a daily or weekly summary if you choose one.",
      action: { label: "Set up alerts", to: "/integrations" },
    },
    {
      key: "owners",
      state: count(f.ownerRules),
      title: "Set who owns what",
      benefit: "So each issue reaches the right person or team without you forwarding it.",
      after: "New issues are assigned by project, asset or layer, and each person can list just the issues assigned to them.",
      action: { label: "Add owner rules", to: "/people/owners" },
    },
    {
      key: "policy",
      state: policyState(f),
      title: "Set how issues are prioritised and fixed",
      benefit: "So priorities and fix deadlines match how your team works, such as which environments count as production.",
      after: "Priorities and due dates follow your rules, and Fixes lists the work in that order.",
      action: { label: "Review the risk policy", to: "/settings/risk-policy" },
      ...(f.remediationPaid
        ? {}
        : {
            locked: {
              plan: "Pro",
              text: "Automatic fixes under policies you approve are part of Stackurity Pro.",
              to: "/settings/automatic-fixes",
            },
          }),
    },
    {
      key: "invite",
      state: flag(f.steps.invite),
      title: "Invite your team",
      benefit: "So the people who fix things see their issues directly, with only the access you give them.",
      after: "Teammates sign in to their own projects, and can be made owners of issues.",
      action: { label: "Invite people", to: "/people" },
    },
    {
      key: "assistant",
      state: flag(f.steps.assistant),
      title: "Connect an AI assistant",
      benefit: "So you can ask Claude, ChatGPT or your editor what is installed and what to upgrade, in plain words.",
      after: "Your assistant answers from your Stackurity data, with links back to the issues.",
      action: { label: "Connect an assistant", to: "/integrations/ai-assistants" },
    },
    {
      key: "mfa",
      state: f.mfa ? "done" : "todo",
      title: "Set up two-factor sign-in",
      benefit: "So a leaked password alone cannot open an admin account that can change everything.",
      after: "Signing in asks for your passkey or code too. A passkey takes a minute.",
      action: { label: "Set up two-factor", to: "/account?return=%2F#mfa" },
    },
  );
  return items;
}

/** The risk policy was saved, or (on a paid plan) an automatic-fix policy exists. */
function policyState(f: SetupFacts): SetupState {
  if (f.riskPolicySaved || (f.remediationPolicies ?? 0) > 0) return "done";
  if (f.riskPolicySaved == null) return "unknown";
  return "todo";
}

export interface SetupProgress {
  done: number;
  total: number;
  /** 0–100, rounded down so it reaches 100 only when every step is done. */
  percent: number;
  complete: boolean;
  /** The first step not done yet (its button is the primary one). */
  next: SetupItem | null;
}

export function setupProgress(items: SetupItem[]): SetupProgress {
  const done = items.filter((i) => i.state === "done").length;
  const total = items.length;
  return {
    done,
    total,
    percent: total ? Math.floor((done * 100) / total) : 100,
    complete: done === total,
    next: items.find((i) => i.state !== "done") ?? null,
  };
}

/** "3 of 8 done". */
export function progressText(p: SetupProgress): string {
  return p.complete ? `All ${p.total} done` : `${p.done} of ${p.total} done`;
}
