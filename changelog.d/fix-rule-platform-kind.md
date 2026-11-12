### Fixed

- **Integration rules limited to platform incidents save again.** Ticking **platform** under **Incident kinds** on a Slack (or any other) integration made **Save changes** fail with "kinds may contain ...", because the server did not accept that kind. It now accepts every kind the dashboard offers, and a test keeps the two lists the same.
