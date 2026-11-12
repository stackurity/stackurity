### Fixed

- **GitLab groups go into the Stackurity project you choose.** Assets from Connect GitLab were added to no project, so people with project access never saw them and their findings showed only under "All projects". When you pick a GitLab group you now choose its project (the one selected at the top is the default), and each group can have its own. For a group connected before, choose its project under Integrations → GitLab: its assets that are in no project are added to it.

### Upgrading

- Migration `0107_gitlab_connection_project` adds the chosen project to `gitlab_connections` (one nullable column). Existing connections keep their assets where they are until a project is chosen.
