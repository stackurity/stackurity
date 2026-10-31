---
name: explain-cve
description: Explain a CVE or advisory (CVE-..., GHSA-...) for the user's own stack using Stackurity - where it is installed, whether it is fixed, how urgent it is and what to upgrade to. Use when the user asks about a specific CVE, advisory or vulnerable package and whether it affects them.
argument-hint: "<CVE-id or package>"
---

# Explain this CVE for my stack

Use the Stackurity MCP tools (server `stackurity`). If the tools are missing or
ask for sign-in, tell the user to run `/mcp`, choose the Stackurity server and
sign in.

The CVE, advisory id or package is in $ARGUMENTS or the conversation. If
there is none, ask for it.

1. **Where it is.** Call `search` with the id. For a package, also call
   `find_component` to see every version installed and where.
2. **The issues.** Call `list_findings` with `query` set to the id to get
   each open issue, then `get_finding` on one or two for the advisory
   details, the installed and fixed versions, and the history.
3. **Why it matters here.** Call `explain_finding` on the most urgent one for
   its priority reasons (known exploited, EPSS, severity, environment, SOS
   rules).
4. **What to do.** Call `upgrade_recommendation` for the package to get the
   version to move to from Stackurity's stored data.
5. **Answer** in this order, briefly:
   - what the vulnerability is, in two sentences, from the advisory text;
   - where it affects the user: count of assets and the versions installed;
   - how urgent, with the reasons the tools gave;
   - the fix: the recommended version, and whether that is a major upgrade;
   - anything closed already (fixed, not affected by VEX, ignored).

Say plainly when Stackurity has no record of the id: the user may not run the
affected package, or it may not be inventoried yet. Do not fill gaps from
memory without saying so.
