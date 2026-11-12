### Fixed

- **Ask Stackurity ranks "what should I fix first" across every asset.** The fix list for a whole workspace was too long for Ask to read, so it narrowed to one server and gave that server's top fixes as if they were the workspace's. `action_plan` now takes a `limit` (the most urgent N actions across every asset), and Ask uses it for these questions, ranks by priority then known-exploited, and says which assets it left out when it looks at only some. "What Ask looked at" shows "Reading the fixes for every asset" for that read.
