---
'@exortek/oidc': major
---

OpenID Provider and relying-party hardening.

- `endSessionHandler` verifies `id_token_hint` against the OP's published JWKS (or signing key) before using its `sub`; previously an unsigned hint could name any user and force their logout. Expired hints are accepted for `logout.idTokenHintMaxAge` (default `'30d'`). A `client_id` parameter must match the hint's audience, `onLogout` also receives `clientId`, and `postLogoutRedirectUris` may be a `{ [clientId]: uris }` map.
- `handleCallback` enforces requested `max_age` (`auth_time`) and `acr_values` (`acr`), throwing the new `AUTHENTICATION_REQUIREMENTS_NOT_MET` (401). `createClient` accepts `maxAge` / `acrValues` defaults that are sent and enforced on every flow.
- The UserInfo endpoint only reads the access token from the `Authorization` header (no `access_token` query parameter).
- `session.cookieName` must be an RFC 6265 token and is regex-escaped in the check-session iframe.

**Migration**

- Publish the OP's verification keys via `jwks` (or keep the signing key), and handle `onLogout` calls with `sub: undefined` for unverifiable hints.
- Send UserInfo requests with `Authorization: Bearer`.
- If you pass `maxAge` / `acrValues` to `authorize()` per call, pass the same values to `handleCallback()` (or set them on `createClient`).
