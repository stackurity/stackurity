### Added

- **Ask Stackurity reads the Help articles.** A new read-only tool, `read_help`, returns a Help article's steps (by id, or the best matches for a few words), so "How do I add a server?" or "How do I connect Slack?" is answered from the same steps people read in Help, with a link to the article and to the page where it is done. AI assistants connected over MCP get the tool too (23 read-only tools). The articles are generated into `internal/helpdocs/articles.json` by `npm run help-json` in `web/`; a web test fails when it is out of date.
- **Buttons under Ask's answers for the pages they point to:** "Open Integrations →", "Read: Add a server →", up to three, the same targets as the answer's own links.

### Changed

- **Ask Stackurity prompt version `2026-11-21.3`:** how-to questions are answered from `read_help`, never from memory; when no article covers it, Ask says so.
