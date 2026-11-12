### Fixed

- **Alerts now cover assets in no project.** The alert rule made while setting up Stackurity was limited to the first project, so issues on assets added later outside it (for example repositories from a GitLab group, listed only under All projects) sent nothing to Slack or email. New setups make a rule for every asset, and Integrations warns when every rule is limited to a project, with how to add one for the whole organisation.
