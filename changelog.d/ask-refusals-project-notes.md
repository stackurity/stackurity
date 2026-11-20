### Added

- **Ask Stackurity: notes about a project.** A project's admins (an organisation-wide admin, or an admin grant on the project) can write a short note about it, up to 2,000 characters, under **Notes for Ask Stackurity** on the project's page (or its Notifications page for admins of that project only): what the project is, which hosts are for testing, what to leave out. Ask reads it with questions about that project, inside the question's context block and marked as written by an organisation administrator, as background and never as instructions. Anyone who can see the project can read the note; every change is in the audit log (`project.ask_notes_update`) with the old and new text. `GET` and `PUT /api/v1/projects/{id}/ask-notes`. See [api.md](docs/api.md).
- **Ask Stackurity: refused and incomplete answers are counted.** Each answer call records why it ended without a full answer (`incomplete_reason`: `refusal`, `cannot_answer`, `tool_error`, `max_tokens`, `tool_budget`, `too_long`) and, for a refusal, the provider's category, without any text. The daily totals count refusals and incomplete answers, `GET /api/v1/ask/usage/calls` and `GET /api/v1/admin/ask/calls` carry the new fields, and `GET /api/v1/admin/ask/feedback/incomplete` (operators and feedback review tokens) gives the counts per day, model and reason. A refused answer is answered again on the next model up, as before; its retry is now recorded with the step-up reason `refusal` instead of `not_found`.

### Changed

- **Ask Stackurity prompt version `2026-11-21.1`:** the system prompt explains project notes and how to treat them.

### Upgrading

- Migration `0119_ask_incomplete_project_notes` adds `incomplete_reason` and `refusal_category` to `ask_api_calls`, `refusals` and `incomplete` to `ask_api_calls_daily`, and `ask_notes` and `ask_notes_updated_at` to `projects`. Additive, with constant defaults.
