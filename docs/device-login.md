# Signing in a terminal from the browser

A command-line tool such as `stackurity-scan --upload` can sign a person in through their browser, with no API token to create, copy or paste. Stackurity implements the OAuth 2.0 Device Authorization Grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)), the flow `gh auth login` and cloud CLIs use.

It is for people at a terminal. CI jobs keep using [keyless CI tokens](install.md#scans-in-ci-without-a-stored-secret) (`POST /ci/token`) or a collector token; servers use the agent and an install code.

## What the person sees

1. The tool prints a code such as `BCDF-GHJK` and the address `https://<your server>/device` (and may open it).
2. In the browser they sign in, or sign up on Stackurity Cloud. After signing in, or after confirming a new account by email, the browser comes back to `/device` with the code.
3. The page shows which tool is asking, the computer name it reported, the address the request came from, the organisation, and exactly what approving allows. People in several organisations choose one; administrators may choose a project for the assets the tool creates.
4. When the request came from a different network than the browser (another IPv4 /24 or IPv6 /48), the page says so and to deny it unless the person started it on another computer, such as a server over SSH.
5. **Approve** or **Deny**. The tool finishes by itself within a few seconds.

Approving needs the **Engineer** role or above for the whole organisation, the same as uploading with an API token of your own. Where the organisation's two-factor policy requires a second factor of the person, they must also have confirmed one in the last 15 minutes: the page asks for it (a passkey, or a code from the app or email) before it offers **Approve**, because approving creates a credential. Single sign-on sessions are left to the identity provider, as by the policy. Someone with access to some projects only, or a viewer, sees why they cannot approve; they can still deny.

Codes are eight letters from an alphabet without vowels or look-alike characters (`BCDFGHJKLMNPQRSTVWXZ`), case and the hyphen do not matter, and each works once, for 10 minutes.

## The token

Approving makes an ordinary API token of the person who approved, listed under **Integrations → API tokens** as *upload only* and named after the tool and computer (`stackurity-scan on laptop-1`). The tool gets its secret once, on its next poll; until then the token is listed with the prefix `stk_pending` and works for nobody.

The token:

- has the collector role and may only `POST /api/v1/ingest`, `POST /api/v1/sbom/import`, read `GET /api/v1/collections/{id}/result` of its own uploads and `GET /api/v1/meta`; every other request answers `403`;
- adds the assets it creates to the chosen project, if an administrator chose one (`project_id` on an upload may name that project, never another);
- works only while its person is a member of the organisation with the Engineer role or above, organisation-wide;
- expires after 90 days, and is revoked like the person's other tokens: in Settings, by a password change or reset that revokes API tokens, or when the organisation starts requiring single sign-on and its administrator revokes people's tokens;
- counts towards a plan's limit on API tokens (Approve answers `402 plan_limit` past it).

An approved request whose tool never collects the token within the 10 minutes has its token revoked.

Every approval emails the person who approved it (in the usual account email layout, which cannot be turned off): which token was made, for which organisation, the address the request came from and the approver's own, and a link to **Integrations → API tokens** to revoke it. A code someone was tricked into approving is then noticed by the person it affects.

## Security

- Only hashes of the device code and the user code are stored (migration `0113_device_authorizations`). Tokens, codes and request bodies are never logged.
- Approve and Deny need a signed-in browser session (never an API token), the dashboard's `X-Stackurity-CSRF` header and the `SameSite=Strict` session cookie; a browser that says the request came from another site (`Sec-Fetch-Site`) is refused.
- The page names the tool from the server's own list (`stackurity-scan`, `stackurity`), not from the request, and warns to approve only a sign-in you started yourself just now: anyone can start a request and send you its code.
- Rate limits: 10 new requests a minute and 60 an hour per address; 120 polls a minute per address (answered `slow_down`); polling faster than the interval answers `slow_down` and lengthens it by 5 seconds; 20 codes per person and 40 per address in 15 minutes on the page; and 1,000 wrong codes in 15 minutes on the whole server, after which the page refuses every code until the window ends (logged as a warning), so guessing spread over many accounts and addresses gets nowhere either.
- Every 5 minutes the server revokes the token of an approved request its tool never collected, and deletes requests that ended more than a day ago.
- Audit log: `device.approve` (with `token.create`, `via: device_login`), `device.deny`, and `device.token_collected` when the tool picks the token up.

## Turning it on

It needs `STACKURITY_BASE_URL`, the server's public address, which the tool shows the person. Without it, `GET /api/v1/meta` does not list `device_login` and the endpoints answer `404 not_configured`. Stackurity Cloud has it on. On a self-hosted server without its [free key](install.md#the-free-key), the approval page answers `403 key_required` until the key is added.

## For tool authors

Check that `GET /api/v1/meta` lists `device_login` in `features`, then:

```
POST /api/v1/device/code
Content-Type: application/x-www-form-urlencoded

client_id=stackurity-scan&host=laptop-1
```

```json
{"device_code": "stkd_…", "user_code": "BCDF-GHJK", "verification_uri": "https://app.stackurity.dev/device",
 "verification_uri_complete": "https://app.stackurity.dev/device?user_code=BCDF-GHJK", "expires_in": 600, "interval": 5}
```

Show `user_code` and `verification_uri`, then poll every `interval` seconds:

```
POST /api/v1/device/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=stkd_…&client_id=stackurity-scan
```

Until the person decides the answer is `400 {"error": "authorization_pending"}`. Other errors: `slow_down` (wait the new `interval`), `access_denied`, `expired_token` (start again), `invalid_grant` (unknown, another client's, or already collected). Once approved:

```json
{"access_token": "stk_…", "token_type": "Bearer", "scope": "upload", "expires_in": 7775990,
 "token": {"id": 12, "name": "stackurity-scan on laptop-1", "prefix": "stk_abcdefgh", "expires_at": "…"},
 "workspace": {"id": 3, "name": "Acme", "slug": "acme"}, "project": null,
 "user": {"email": "asha@acme.example"}, "server_url": "https://app.stackurity.dev"}
```

Send `access_token` as `Authorization: Bearer` on uploads. JSON bodies work as well as forms, and neither request needs credentials or the `X-Stackurity-CSRF` header. Full details: [api.md](api.md#post-devicecode).
