### Fixed

- **Outcomes explains its SLA the way it now measures it.** The page still said the SLA counts the policy's days from first detection, though since 0.19.7 it compares each fix with that issue's fix-by date. The note, the SLA card and its "Policy days" column now say so.
- **A finding's upgrade card no longer gives a second issue count.** It said "minimum for all 37 open issues" next to the fix's "36 issues cleared together", because its list also holds the package's end-of-life entry. The row now reads "minimum for everything it resolves", and the resolves list below shows what that is.
