### Changed

- The API reference (`/api/v1/openapi.json`) describes the request and response bodies of signing in (`POST /auth/login`, including the second-factor answer), `POST /auth/mfa/verify`, `POST /auth/password` and `GET /auth/me`, with examples, instead of a bare object; `POST /auth/logout` no longer asks for a body. A test keeps the user and sign-in schemas in step with the code.
- The API reference also describes what `GET /assets`, `GET /assets/{id}` and `GET /findings` return (`Asset`, `Identifier`, `Reporting`, `Finding`, `FindingVEX` and the paged list), and the same test keeps those schemas in step with the store types.
