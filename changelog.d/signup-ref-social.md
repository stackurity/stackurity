### Fixed

- **Sign-ups with Google, Microsoft or GitHub record where they came from.** The sign-up page keeps its `?ref=` in the tab while the person is at the provider and sends it with the completion form (`POST /signup/social` takes `ref`), so the trial report's `ref` is no longer empty for them. Without a `ref`, a link tagged `utm_source` (and `utm_campaign`) counts as `<utm_source>-<utm_campaign>`, for the email form too.
