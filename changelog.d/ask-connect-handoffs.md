### Added

- **Ask Stackurity can start a connection for you.** Ask it to connect GitHub, GitLab, Jira, PagerDuty or Slack, and the card under its answer has one button that starts the same flow as the Integrations page: you approve Stackurity on the service's own page and come back with the Ask panel still open. For Microsoft Teams, email and webhook alerts and DigitalOcean, the card links to the setup page. For a new server, **Apply** creates an install code as you and the card shows the install command with **Copy**; the code is shown once and Ask never sees it. The card says **Connected** when it finds the new connection. Only organisation admins get these cards, and they need **Ask may propose changes**. See [Ask Stackurity](docs/ai-assistants.md#ask-stackurity).

### Security

- **Secrets pasted into Ask Stackurity are removed before the model sees them.** A token, password, key or webhook address in a known shape is taken out of the question before it is stored, used as the conversation's title or sent to the model, and the panel warns you, also while you type. Ask never asks for or accepts a secret: you enter it on the setup page.

### Upgrading

- Migration `0107_ask_handoffs` lets `ask_proposals` hold connection hand-offs (`tool` `connect`, status `started`).
