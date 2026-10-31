---
name: triage-issues
description: Triage the user's open Stackurity issues and say what to fix first. Use when the user asks to triage, prioritise or review their Stackurity issues, findings or vulnerabilities, or asks "what should we fix first", for one project, asset or the whole organisation.
argument-hint: "[project or asset name]"
---

# Triage my Stackurity issues

Use the Stackurity MCP tools (server `stackurity`). They only read unless the
user allowed changes when connecting. If the tools are missing or ask for
sign-in, tell the user to run `/mcp`, choose the Stackurity server and sign in.

1. **Scope.** If the user named a project, asset or team ($ARGUMENTS), find it
   with `search` or `list_assets`. Otherwise work across everything the
   connection can see, and say so.
2. **What to fix first.** Call `action_plan` (with `asset_id` when scoped).
   Each group is one change (a package upgrade, OS updates, a release
   upgrade) with the packages, target versions and how many issues it clears.
3. **Why.** For the top three groups, call `explain_finding` on one issue in
   each to cite why it has its priority (known exploited, EPSS, severity,
   reachability, SOS rules). Do not invent reasons the tools do not give.
4. **Report** as a short ranked list, most urgent first:
   - the change, in one line (package, from → to version, where);
   - issues cleared and the top priority (P1–P4), and known exploited if so;
   - effort (low, medium, high) and whether it is a major upgrade;
   - the one-line reason from `explain_finding`.
   Then one line on what can wait, and anything with no fix yet.
5. **Next step.** Offer to explain one issue (the `explain-cve` skill) or draft
   the upgrade (the `upgrade-pr` skill). Only if the user asks, and only when
   the connection allows changes, offer `assign` or `snooze`; describe the
   change and wait for a yes before calling a write tool.

Keep numbers exactly as the tools return them. If a tool returns nothing,
say what you looked at instead of guessing.
