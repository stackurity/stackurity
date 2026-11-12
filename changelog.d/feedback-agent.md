### Added

- **Feedback is worked on as it arrives.** A feedback agent (`tools/feedback-agent`, run on the team's Mac every ten minutes) builds safe changes as pull requests with tests, asks the sender when something is unclear, and holds anything about billing, sign-in and permissions, customer wording, legal text, data deletion, AI prompts or costs for the owner's approval. It never merges or deploys. See [Feedback queue](docs/feedback-queue.md#the-feedback-agent).
- **My feedback shows the conversation.** Questions and updates from the Stackurity team (and its automated feedback agent, labelled as such) appear under each item you sent, and you can reply while it is open. A new status, "Needs your answer", says when the team is waiting for you. See [API](docs/api.md#post-feedbackminerefreply).
- **Admin → Feedback** (on the server that runs the feedback queue only): the queue with what needs approval first, each item's description, page, browser, attachments (signed download links), thread and pull request, and Approve, Decline and Reply. Approving needs an instance administrator signed in to the dashboard; API and triage tokens cannot.
- New feedback emails, off until their wording is approved: received and needs-more-details to the sender (`STACKURITY_FEEDBACK_AGENT_EMAILS`), and "approval needed" to `STACKURITY_FEEDBACK_APPROVERS`.

### Upgrading

- Migration `0105_feedback_agent` adds the `needs_info` status, the approval columns and `feedback_comments` to the feedback queue, and `thread` to `feedback_sent`. Additive.
