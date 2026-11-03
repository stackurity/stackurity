import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  auditEmpty,
  automaticFixesEmpty,
  awsEmpty,
  checksEmpty,
  deliveriesEmpty,
  ignoreRulesEmpty,
  incidentsEmpty,
  jobsEmpty,
  leaksEmpty,
  OWNER_RULES_EMPTY,
  PLUGINS_EMPTY,
  PROJECTS_EMPTY,
  requestsEmpty,
  secretsEmpty,
  sourcesEmpty,
  teamsEmpty,
  tokensEmpty,
  vexEmpty,
  type EmptyCopy,
} from "./emptyCopy.ts";

// Each empty list says why it is empty, what fills it and what appears
// then; an action a role cannot use is never offered, and the line instead
// says who can.

/** An unfiltered empty list explains itself: why, and what appears after. */
function explains(c: EmptyCopy) {
  assert.ok(c.title, "title");
  assert.ok(c.why, `${c.title}: why`);
  assert.ok(c.after, `${c.title}: after`);
}

test("leaked keys: nothing scanned is not all clear, and only an admin gets Add a server", () => {
  for (const view of ["action", "kept", "resolved"] as const) {
    const none = leaksEmpty(view, 0, true);
    explains(none);
    assert.equal(none.title, "No files scanned for keys yet");
    assert.match(none.why!, /does not mean there are none/);
    assert.deepEqual([none.action?.label, none.action?.to, none.action?.permitted], ["Add a server", "/assets/add", true]);
    const viewer = leaksEmpty(view, 0, false);
    assert.equal(viewer.action?.permitted, false);
    assert.match(viewer.action!.otherwise!, /An administrator can add servers/);
  }
  const clear = leaksEmpty("action", 3, false);
  explains(clear);
  assert.equal(clear.title, "No leaked keys need action");
  assert.equal(clear.why, "Scans of 3 assets found no key that needs rotating.");
  assert.equal(clear.action, undefined);
  assert.equal(leaksEmpty("kept", 1, true).why, "Scans of 1 asset found no keys kept in configuration files.");
  explains(leaksEmpty("resolved", 2, true));
  // One asset's tab: its own notice says when it was never scanned.
  const asset = leaksEmpty("action", undefined, true);
  assert.equal(asset.title, "No leaked keys need action");
  assert.doesNotMatch(asset.why!, /Scans of/);
});

test("approvals: deciders are told who asks; others are sent to ask", () => {
  for (const status of ["pending", "all"] as const) {
    const decider = requestsEmpty(status, true);
    explains(decider);
    assert.equal(decider.action, undefined);
    const asker = requestsEmpty(status, false);
    explains(asker);
    assert.deepEqual(asker.action, { label: "Go to issues", to: "/fixes/issues", permitted: true });
  }
  assert.equal(requestsEmpty("pending", true).title, "No requests waiting");
  assert.equal(requestsEmpty("all", false).why, "You have not asked to ignore an issue yet.");
  explains(ignoreRulesEmpty(false));
  assert.equal(ignoreRulesEmpty(true).title, "No ignore rules yet");
});

test("sources: an admin gets Add integration, others are told who can", () => {
  const admin = sourcesEmpty(true);
  explains(admin);
  assert.deepEqual([admin.action?.label, admin.action?.permitted], ["Add integration", true]);
  const engineer = sourcesEmpty(false);
  assert.equal(engineer.action?.permitted, false);
  assert.match(engineer.action!.otherwise!, /^An administrator can add/);
});

test("deliveries: no channel, channels but nothing sent, and filters read differently", () => {
  const none = deliveriesEmpty(0, false, true);
  explains(none);
  assert.equal(none.title, "Nothing to deliver to yet");
  assert.deepEqual([none.action?.to, none.action?.permitted], ["/integrations", true]);
  assert.equal(deliveriesEmpty(0, false, false).action?.permitted, false);
  const quiet = deliveriesEmpty(2, false, true);
  explains(quiet);
  assert.equal(quiet.title, "No messages sent yet");
  assert.equal(quiet.action, undefined);
  // Still loading the channels: never claims none are set up.
  assert.equal(deliveriesEmpty(undefined, false, true).title, "No messages sent yet");
  assert.equal(deliveriesEmpty(0, true, true).title, "No deliveries match these filters");
});

test("checks: Go to fixes only for those who can check again; filters say what they hide", () => {
  const all = checksEmpty({ asset: false, waiting: false }, true);
  explains(all);
  assert.deepEqual([all.action?.label, all.action?.to, all.action?.permitted], ["Go to fixes", "/fixes", true]);
  const viewer = checksEmpty({ asset: false, waiting: false }, false);
  assert.equal(viewer.action?.permitted, false);
  assert.match(viewer.action!.otherwise!, /engineer or above/);
  assert.equal(checksEmpty({ asset: false, waiting: true }, true).title, "No checks waiting");
  assert.equal(checksEmpty({ asset: true, waiting: false }, true).title, "No checks for this asset");
  assert.equal(checksEmpty({ asset: true, waiting: false }, true).action, undefined);
});

test("plugins, owner rules, teams, projects, secrets: admin pages explain and offer their form", () => {
  explains(PLUGINS_EMPTY);
  explains(OWNER_RULES_EMPTY);
  assert.equal(OWNER_RULES_EMPTY.action?.label, "Add rule");
  explains(teamsEmpty(true));
  assert.equal(teamsEmpty(false).action, undefined);
  explains(PROJECTS_EMPTY);
  explains(secretsEmpty(true));
  assert.equal(secretsEmpty(false).action, undefined);
});

test("incidents: nothing reporting is not all clear", () => {
  const nothing = incidentsEmpty(false, true, true);
  explains(nothing);
  assert.equal(nothing.title, "No incidents yet");
  assert.equal(nothing.action?.to, "/assets/add");
  assert.equal(incidentsEmpty(false, true, false).action?.permitted, false);
  const clear = incidentsEmpty(false, false, false);
  explains(clear);
  assert.equal(clear.title, "No open incidents");
  assert.equal(clear.action, undefined);
  assert.equal(incidentsEmpty(false, false, true).action?.to, "/integrations");
  assert.equal(incidentsEmpty(true, true, true).title, "No incidents match these filters");
});

test("automatic fixes, audit, tokens, VEX, AWS, jobs", () => {
  assert.equal(automaticFixesEmpty(true, true).action?.permitted, true);
  assert.equal(automaticFixesEmpty(false, false).action?.permitted, false);
  // The page's own text already says who turns on a policy.
  assert.equal(automaticFixesEmpty(false, false).action?.otherwise, undefined);
  explains(auditEmpty(false));
  assert.equal(auditEmpty(true).title, "No audit events of this type");
  explains(tokensEmpty(false, true));
  assert.equal(tokensEmpty(true, true).title, "No active tokens");
  assert.doesNotMatch(tokensEmpty(false, false).after!, /above/);
  assert.match(vexEmpty(true).after!, /^Import one above/);
  assert.doesNotMatch(vexEmpty(false).after!, /Import one above/);
  explains(awsEmpty(true));
  assert.equal(awsEmpty(false).after, undefined);
  explains(jobsEmpty(false));
  assert.equal(jobsEmpty(true).title, "No jobs in this state");
});

test("the pages use this copy", () => {
  const uses: [string, RegExp][] = [
    ["components/Leaks.tsx", /<EmptyState \{\.\.\.leaksEmpty\(view, assetId \? undefined : res\.data\.scanned_assets, can\("admin"\)\)\}/],
    ["pages/Approvals.tsx", /<EmptyState \{\.\.\.requestsEmpty\(status, canDecide\)\}/],
    ["pages/Approvals.tsx", /<EmptyState \{\.\.\.ignoreRulesEmpty\(all\)\}/],
    ["pages/Integrations.tsx", /const empty = sourcesEmpty\(admin\)/],
    ["pages/settings/Notifications.tsx", /<EmptyState \{\.\.\.deliveriesEmpty\(/],
    ["pages/Checks.tsx", /<EmptyState \{\.\.\.checksEmpty\(\{ asset: Boolean\(asset\), waiting: open \}, canAct\("engineer"\)\)\}/],
    ["pages/settings/Plugins.tsx", /<EmptyState \{\.\.\.PLUGINS_EMPTY\}/],
    ["pages/settings/Owners.tsx", /<EmptyState \{\.\.\.OWNER_RULES_EMPTY\} action=\{\{ \.\.\.OWNER_RULES_EMPTY\.action!, onClick: \(\) => setEditing\("new"\) \}\}/],
    ["pages/Incidents.tsx", /<EmptyState \{\.\.\.incidentsEmpty\(/],
    ["pages/Remediation.tsx", /<EmptyState \{\.\.\.automaticFixesEmpty\(/],
    ["pages/Audit.tsx", /<EmptyState \{\.\.\.auditEmpty\(/],
    ["pages/settings/Teams.tsx", /<EmptyState \{\.\.\.teamsEmpty\(/],
    ["pages/settings/Projects.tsx", /<EmptyState \{\.\.\.PROJECTS_EMPTY\}/],
    ["pages/settings/Tokens.tsx", /<EmptyState \{\.\.\.tokensEmpty\(/],
    ["pages/settings/Secrets.tsx", /\{\.\.\.secretsEmpty\(/],
    ["pages/settings/Vex.tsx", /<EmptyState \{\.\.\.vexEmpty\(can\("engineer"\)\)\}/],
    ["pages/settings/Aws.tsx", /<EmptyState \{\.\.\.awsEmpty\(/],
    ["pages/settings/Jobs.tsx", /<EmptyState \{\.\.\.jobsEmpty\(/],
  ];
  for (const [file, re] of uses) {
    assert.match(readFileSync(new URL(file, import.meta.url), "utf8"), re, file);
  }
  // The Sources page opens its own Add integration form, not while it is open.
  assert.match(
    readFileSync(new URL("pages/Integrations.tsx", import.meta.url), "utf8"),
    /action=\{empty\.action && !creating \? \{ \.\.\.empty\.action, onClick: \(\) => setCreating\("choose"\) \} : undefined\}/,
  );
});
