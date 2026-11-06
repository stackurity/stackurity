/**
 * What an empty list says: why it is empty, the one thing that fills it,
 * and what appears there then. components/ui.tsx EmptyState renders it.
 * Kept free of React so node --test can load it (emptyCopy.test.ts).
 *
 * "Nothing yet because nothing is connected" and "all clear" read
 * differently, so callers pass what they know (sources scanned, channels
 * set up, filters on). An action the person's role cannot use is never
 * offered: `permitted` false shows `otherwise` (who can) instead.
 */

// format.ts's, repeated: node --test loads this file without a bundler.
function plural(n: number, word: string, many = word + "s"): string {
  return `${n.toLocaleString()} ${n === 1 ? word : many}`;
}

export interface EmptyActionCopy {
  label: string;
  /** The page that fills the list; or the caller adds an onClick. */
  to?: string;
  /** This person may use it (their role); false shows `otherwise`. */
  permitted: boolean;
  /** Who can, for someone who may not: "An administrator can add one." */
  otherwise?: string;
}

export interface EmptyCopy {
  title: string;
  /** Why the list is empty. */
  why?: string;
  /** What appears here once it fills. */
  after?: string;
  action?: EmptyActionCopy;
}

// --- leaked keys (components/Leaks.tsx)

export type LeakViewName = "action" | "kept" | "resolved";

/**
 * scannedAssets: assets whose files were scanned for keys (GET /leaks), or
 * undefined on one asset's tab, which warns of no scan itself.
 */
export function leaksEmpty(view: LeakViewName, scannedAssets: number | undefined, canAddServer: boolean): EmptyCopy {
  if (scannedAssets === 0) {
    return {
      title: "No files scanned for keys yet",
      why: "No agent or scan has checked your assets' files for keys yet, so an empty list does not mean there are none.",
      after: "Agents and stackurity scan from this version on check files for keys when they report. Keys they find appear here, most urgent first.",
      action: { label: "Add a server", to: "/assets/add", permitted: canAddServer, otherwise: "An administrator can add servers." },
    };
  }
  const scanned = scannedAssets ? `Scans of ${plural(scannedAssets, "asset")} ` : "";
  switch (view) {
    case "action":
      return {
        title: "No leaked keys need action",
        why: scanned ? `${scanned}found no key that needs rotating.` : "No key found here needs rotating.",
        after: "If a later scan finds one, it appears here and opens an incident.",
      };
    case "kept":
      return {
        title: "No keys found in configuration files",
        why: scanned ? `${scanned}found no keys kept in configuration files.` : "No keys were found kept in configuration files.",
        after: "Keys kept in configuration files are listed here, where they belong. They never alert.",
      };
    case "resolved":
      return {
        title: "No resolved leaked keys",
        why: "No leaked key has gone from a scan or been dismissed yet.",
        after: "A key appears here once a complete scan no longer sees it, or someone dismisses it.",
      };
  }
}

// --- approvals (pages/Approvals.tsx)

/** canDecide: security and admin users decide; others see their own requests. */
export function requestsEmpty(status: "pending" | "all", canDecide: boolean): EmptyCopy {
  const ask: EmptyActionCopy | undefined = canDecide ? undefined : { label: "Go to issues", to: "/fixes/issues", permitted: true };
  if (status === "pending") {
    return {
      title: "No requests waiting",
      why: canDecide ? "Nobody is waiting for a decision on an issue they asked to ignore." : "None of your requests is waiting for a decision.",
      after: "When someone uses Ask to ignore on an issue or a fix, the request waits here until a security or admin user decides.",
      action: ask,
    };
  }
  return {
    title: "No requests yet",
    why: canDecide ? "Nobody has asked to ignore an issue yet." : "You have not asked to ignore an issue yet.",
    after: "Every request stays here, waiting, approved or declined.",
    action: ask,
  };
}

export function ignoreRulesEmpty(showEnded: boolean): EmptyCopy {
  return {
    title: showEnded ? "No ignore rules yet" : "No ignore rules",
    why: showEnded ? "No issue has ever been ignored." : "No issue is being ignored right now.",
    after: "Approving a request to ignore, or ignoring an issue directly, adds a rule here. Ending a rule returns its issues to new.",
  };
}

// --- integrations

/** Integrations, Sources: repositories, images and plugins run on a schedule. */
export function sourcesEmpty(admin: boolean): EmptyCopy {
  return {
    title: "No sources yet",
    why: "Nothing is collected on a schedule yet: no Git repository, container image or plugin is connected.",
    after: "Each source appears here with its last run and any error. Servers, CI pipelines and SBOM uploads are added from Integrations.",
    action: {
      label: "Add integration",
      permitted: admin,
      otherwise: "An administrator can add Git repositories, container images and plugins.",
    },
  };
}

/** channels: notification integrations set up, or undefined while loading. */
export function deliveriesEmpty(channels: number | undefined, filtered: boolean, admin: boolean): EmptyCopy {
  if (filtered) return { title: "No deliveries match these filters", why: "Try another status or channel." };
  if (channels === 0) {
    return {
      title: "Nothing to deliver to yet",
      why: "No notification integration is set up, so Stackurity has nowhere to send messages.",
      after: "Every message sent, held or failed then appears here, newest first.",
      action: {
        label: "Set up notifications",
        to: "/integrations",
        permitted: admin,
        otherwise: "An administrator can add Slack, email and others under Integrations.",
      },
    };
  }
  return {
    title: "No messages sent yet",
    why: "Notifications are set up, but nothing has been sent through them yet.",
    after: "Each message appears here once Stackurity sends one, with whether it was delivered.",
  };
}

/** Integrations, Plugins, with the plugin directory set but empty. */
export const PLUGINS_EMPTY: EmptyCopy = {
  title: "No plugins installed",
  why: "The plugin directory is set, but there is no plugin in it.",
  after: "Each plugin then appears here with the permissions, credentials and network access it needs, to review before using it.",
};

// --- activity

/** Activity, Checks. canCheck: may press Check again (engineer and above). */
export function checksEmpty(f: { asset: boolean; waiting: boolean }, canCheck: boolean): EmptyCopy {
  if (f.asset || f.waiting) {
    return {
      title: f.waiting ? "No checks waiting" : "No checks for this asset",
      why: f.waiting ? "Every check asked for has its fresh report." : "Nobody has asked for a fresh report on this asset.",
      after: f.asset && !f.waiting ? undefined : "Checks still waiting for a report appear here.",
    };
  }
  return {
    title: "No checks yet",
    why: "Nobody has asked for a fresh report yet.",
    after: "Each Check again or I applied this appears here with what the fresh report showed: fixed, left and new.",
    action: {
      label: "Go to fixes",
      to: "/fixes",
      permitted: canCheck,
      otherwise: "An engineer or above can press Check again on a fix or an asset.",
    },
  };
}

/** Incidents. noAssets: nothing reports yet, so nothing can open one. */
export function incidentsEmpty(filtered: boolean, noAssets: boolean, admin: boolean): EmptyCopy {
  if (filtered) return { title: "No incidents match these filters", why: "Try clearing a filter." };
  if (noAssets) {
    return {
      title: "No incidents yet",
      why: "No asset reports to Stackurity yet, so nothing can open an incident.",
      after: "Incidents then open on their own for prioritised issues and for system problems.",
      action: { label: "Add a server", to: "/assets/add", permitted: admin, otherwise: "An administrator can add servers." },
    };
  }
  return {
    title: "No open incidents",
    why: "No prioritised issue or system problem is open right now.",
    after: "One opens here on its own when that changes. Who is told is set under Integrations.",
    action: admin ? { label: "Choose who is told", to: "/integrations", permitted: true } : undefined,
  };
}

/**
 * Automatic fixes. canPolicy: may turn on a policy (security and above).
 * The page's own text explains plans and who turns a policy on.
 */
export function automaticFixesEmpty(waiting: boolean, canPolicy: boolean): EmptyCopy {
  return {
    title: waiting ? "No automatic fixes waiting for approval" : "No automatic fixes yet",
    action: {
      label: "Turn on a policy",
      to: "/settings/automatic-fixes",
      permitted: canPolicy,
    },
  };
}

/** Audit log. filtered: one object type chosen. */
export function auditEmpty(filtered: boolean): EmptyCopy {
  if (filtered) return { title: "No audit events of this type", why: "Choose All to see every event." };
  return {
    title: "No audit events",
    why: "Nobody has signed in or changed anything through the API yet.",
    after: "Sign-ins and every change appear here, newest first.",
  };
}

// --- people and settings (admin pages: the action is always theirs)

export const OWNER_RULES_EMPTY: EmptyCopy = {
  title: "No owner rules yet",
  why: "Without a rule, new issues stay unassigned until someone assigns them.",
  after: "New issues that match a rule go straight to the person or team it names.",
  action: { label: "Add rule", permitted: true },
};

export function teamsEmpty(canAdd: boolean): EmptyCopy {
  return {
    title: "No teams yet",
    why: "No team exists, so no asset has an owner team for its alerts to go to.",
    after: "Each team appears here with its members, what it can see and what it owns.",
    action: canAdd ? { label: "Add team", permitted: true } : undefined,
  };
}

export const PROJECTS_EMPTY: EmptyCopy = {
  title: "No projects yet",
  why: "Assets are not grouped yet, so access can only be given to everything or to single assets.",
  after: "Each project appears here with its assets. People given a project see only its assets.",
  action: { label: "New project", permitted: true },
};

/** revoked: there are tokens, all revoked (hidden unless Show revoked). */
export function tokensEmpty(revoked: boolean, canCreate: boolean): EmptyCopy {
  return {
    title: revoked ? "No active tokens" : "No tokens yet",
    why: revoked ? "Every token here was revoked. Tick Show revoked to see them." : "No script, CI pipeline or collector has a token yet.",
    after: `${canCreate ? "Create one above. " : ""}Each token appears here with its role, expiry and when it was last used.`,
  };
}

export function secretsEmpty(enabled: boolean): EmptyCopy {
  return {
    title: "No stored credentials yet",
    why: "No token, password or webhook URL is stored for integrations to use.",
    after: "Each secret appears here by name, to use as secret:NAME in an integration or a notification channel.",
    action: enabled ? { label: "Add credential", permitted: true } : undefined,
  };
}

/** canImport: engineer and above see the import form above the list. */
export function vexEmpty(canImport: boolean): EmptyCopy {
  return {
    title: "No VEX imported yet",
    why: "No statement saying a vulnerability does not affect your software has been imported.",
    after: canImport
      ? "Import one above. Each document then appears here with its statements, applied or waiting for approval."
      : "Each imported document appears here with its statements. An engineer or above can import one.",
  };
}

/** enabled: this server can connect AWS with a stack (the form above). */
export function awsEmpty(enabled: boolean): EmptyCopy {
  return {
    title: "No AWS accounts yet",
    why: "No AWS account is connected with a stack, so its managed services are not inventoried this way.",
    after: enabled ? "Launch the stack above. The account appears here once you do." : undefined,
  };
}

export function jobsEmpty(filtered: boolean): EmptyCopy {
  if (filtered) return { title: "No jobs in this state", why: "Choose All to see every job." };
  return {
    title: "No jobs",
    why: "Nothing has run in the background yet.",
    after: "Each background job appears here with its state, attempts and any error.",
  };
}

// --- an asset's Stack tab, "Assets in this stack" (components/Stack.tsx)

export interface StackEmptyCopy extends EmptyCopy {
  /** What to do, in order; `code` in backticks. */
  steps: string[];
}

/**
 * kind: the asset's kind. suggestions: suggested links shown below
 * (GET /assets/{id}/link-suggestions). canEdit: the person may change
 * relations (engineer and above), which linking needs.
 */
export function stackEmpty(kind: string, assetId: number, suggestions: number, canEdit: boolean): StackEmptyCopy {
  const relations: EmptyActionCopy = {
    label: "Open the Relations tab",
    to: `/assets/${assetId}?tab=relations`,
    permitted: canEdit,
    otherwise: "Someone with edit permission can link it.",
  };
  const scan = "Or run `stackurity scan` inside a Git checkout of the repository, so its remote is recorded: an app the agent finds deployed from the same remote is then linked by itself.";
  switch (kind) {
    case "repository":
      return {
        title: "Not linked to a deployment yet",
        why: "We don't know where this code is deployed yet.",
        after: "When the agent finds the deployed app, or you link it below, its server and live issues appear here.",
        steps: [
          ...(suggestions > 0 ? [`Link ${suggestions === 1 ? "the suggested app" : "one of the suggested apps"} below, if it is right.`] : []),
          "Link it by hand on the Relations tab: the app is built from this repository.",
          scan,
        ],
        action: relations,
      };
    case "application":
      return {
        title: "Not linked to its server or repository yet",
        why: "We don't know which server runs this app or which repository it is built from yet.",
        after: "When the agent reports it, or you link it below, its server, its code and their issues appear here.",
        steps: [
          ...(suggestions > 0 ? [`Link ${suggestions === 1 ? "the suggested repository" : "one of the suggested repositories"} below, if it is right.`] : []),
          "Link it by hand on the Relations tab.",
          scan,
        ],
        action: relations,
      };
    case "host":
      return {
        title: "No applications found on this server yet",
        why: "The agent has not reported an application running here.",
        after: "Applications the agent finds on this server appear here with their libraries and issues.",
        steps: [],
      };
    default:
      return {
        title: "Nothing linked to this asset yet",
        why: "No other asset is linked to this one.",
        after: "Assets you link on the Relations tab appear here with their issues.",
        steps: [],
        action: relations,
      };
  }
}
