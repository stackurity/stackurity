---
name: upgrade-pr
description: Write the upgrade pull request for a vulnerable package Stackurity reports - bump the version in this repository, run the tests and draft the PR description with the issues it clears. Use when the user asks to fix, upgrade or patch a package Stackurity flagged, or to "write the upgrade PR".
argument-hint: "<package or fix>"
disable-model-invocation: true
---

# Write the upgrade PR

This changes code, so it runs only when the user asks for it. Use the
Stackurity MCP tools (server `stackurity`) for what to upgrade, and this
repository's own tooling for the change. If the Stackurity tools are missing
or ask for sign-in, tell the user to run `/mcp` and sign in.

1. **What to upgrade.** From $ARGUMENTS or the conversation, find the package.
   Call `action_plan` or `remediation_plan` for this repository's asset (find
   it with `list_assets` or `search` by the repository name) and pick the
   group for the package. Note its `from` and target versions and the issues
   it clears.
2. **Check the target.** Call `upgrade_recommendation` for the package. Prefer
   the recommended version in the same major line; if only a major upgrade
   fixes it, say so and ask before going on.
3. **Make the change** on a new branch, with the ecosystem's own tool (for
   example `npm install pkg@x.y.z`, `go get pkg@vX.Y.Z`, `pip-compile`,
   `bundle update pkg`, `composer require pkg:x.y.z`). Update the lock file.
   Do not hand-edit lock files.
4. **Test.** Run the project's tests and build. If they fail, read the
   package's changelog between the two versions and fix what the upgrade
   broke, or stop and report.
5. **Draft the PR** (do not push or open it unless the user says so):
   - title: `Upgrade <package> from <from> to <to>`;
   - the advisories it fixes (ids from Stackurity) and their priorities;
   - breaking changes from the changelog, and what you changed for them;
   - how it was tested.
6. **After merge.** Tell the user Stackurity marks the issues fixed after the
   next scan, and that `verify_since` (or Check again in Stackurity) confirms
   it.

Never put asset names, hostnames or internal URLs from Stackurity into a
public PR description unless the user asks.
