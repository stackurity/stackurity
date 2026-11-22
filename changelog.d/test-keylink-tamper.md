### Fixed

- Tests: the key-link test's "tampered" key now always changes the signature. Replacing its last four characters could, about once in 65,000 runs, decode to the same signature and fail CI.
- Tests: the invitation rate-limit test waits for a fresh window when it starts close to the end of the minute or hour, so a run that straddles a window boundary no longer sees one request too many.
