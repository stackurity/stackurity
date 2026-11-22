### Fixed

- Tests: the key-link test's "tampered" key now always changes the signature. Replacing its last four characters could, about once in 65,000 runs, decode to the same signature and fail CI.
