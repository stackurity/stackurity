# Running a Stackurity pilot

A pilot answers one question: **does Stackurity find something important on your estate that you did not know about, and does it help you fix it?** It takes two to four weeks and about two hours of your team's time.

## Two ways to run it

| | Stackurity Cloud | On your own server |
|---|---|---|
| What you install | Only the agents and, if you like, a CI step | Stackurity itself (Docker Compose or Helm) plus the agents |
| How to start | Sign up at [app.stackurity.dev](https://app.stackurity.dev) for a 14-day free trial, no card needed | [install.md](install.md) |
| Where your inventory lives | In your own organisation on app.stackurity.dev, isolated from every other organisation by the database itself. If you do not choose a [plan](https://stackurity.dev/pricing.html) by the end of the trial, the organisation becomes read-only (you can still sign in and export), and its data is deleted after 30 days read-only | On your server; nothing leaves it except anonymous downloads of public vulnerability data |
| Setup time | About 15 minutes | About 30 minutes |
| Best when | You want to see results quickly | Your policies do not allow inventory data to leave your network |

Both run the same release, and everything in the [Community edition](editions.md) is available. The Cloud trial includes the Pro features of the Team plan, with up to 20 assets and 3 projects, and its reports are shortened and marked as a trial. On your own server, Pro features (automatic fixing, several teams, the evidence report, single sign-on) can be switched on for the pilot with a time-limited licence.

## Week by week

**Day 1: connect.** About 30 minutes together on a call.
- Install the agent on a few Linux servers, including at least one in production (**Assets → Add server** gives a one-line command; the agent is read-only and unprivileged, see [install.md](install.md)).
- Add two or three repositories under **Settings → Integrations**, or add [`stackurity/scan-action`](https://github.com/marketplace/actions/stackurity-scan) to one CI pipeline.
- Optional: container images, a Kubernetes cluster ([kubernetes.md](kubernetes.md)) or AWS managed services.

**Week 1: look.** On your own, 30 to 60 minutes.
- Open the **Dashboard**: what needs you now and the top fixes, most urgent first, each with the version to move to and what it fixes. **Fixes** lists all of them.
- Open a few findings and read "How this was decided": the advisory, the version rules and the evidence.
- Check **Coverage**: what Stackurity could not check, and why. Nothing unchecked is ever shown as clean.

**Week 2 to 3: act.** As part of normal work.
- Apply a few of the recommended upgrades and watch the findings close once the next inventory confirms the new version.
- Route alerts to Slack, Teams, email or Jira if you want them.
- Tell us whenever something looks wrong (see below).

**End: review.** A 30-minute call: what was useful, what was noise, what was missing.

## Telling us when something is wrong

This is the most valuable part of a pilot. Use the forms on GitHub (or email info@stackurity.ai if you prefer not to post publicly):

- [Wrong finding](https://github.com/stackurity/stackurity/issues/new?template=wrong-finding.yml): a vulnerability that does not apply, for example because your distribution backported the fix.
- [Missed vulnerability](https://github.com/stackurity/stackurity/issues/new?template=missed-vulnerability.yml): a known issue Stackurity did not report.
- [Coverage gap](https://github.com/stackurity/stackurity/issues/new?template=coverage-gap.yml): something marked "not checked" that you need covered.

Every confirmed wrong or missed finding becomes a permanent test case in the matching corpus, so the same mistake cannot come back. Never include secrets, tokens, internal hostnames or IP addresses: package names and versions are enough.

## What we measure

We share these with you at the end:

- **Important findings you did not know about**: exploited or critical vulnerabilities, end-of-life software in production, outdated runtimes.
- **Fixes made because of Stackurity**, and how long they took.
- **Wrong and missed findings** reported, and whether they were fixed.
- **Coverage**: how much of what you run Stackurity could check, and what it could not.
- **Time to first useful result** after connecting.
- **Noise**: findings you considered irrelevant, and why.

## What we need from you

- One contact who can install agents and add a repository.
- Two hours over the pilot: the setup call, a look at the action plan, the review call.
- Honest feedback, including "this was not useful".

To start a pilot, [get in touch](https://stackurity.dev/#contact).
