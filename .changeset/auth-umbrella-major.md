---
'@exortek/auth': major
---

- Re-exports the new majors of `challenge`, `crypto`, `jwe`, `jwt`, `magic-link`, `oauth2`, `oidc`, `opaque`, `paseto`, `passkey`, `password`, `security` and `session`. These majors carry security fixes from a repo-wide audit, and several make an unsafe default an error.
- The umbrella's own surface is unchanged: it still re-exports every package as a namespace and from each subpath.

**Migration:** follow the **Migration** notes in each re-exported package's CHANGELOG for this release. The changes most likely to affect existing code:
- PASETO keys are now typed (`keys.local(...)` / `keys.secret(...)` / `keys.public(...)`).
- crypto, session and trusted-device secrets must be at least 32 bytes.
- `session` impersonation requires an authorize hook.
- opaque tokens are random-only and `create()` requires `expiresIn`.
- `challenge` single-use tokens must be consumed.
- `magic-link` normalizes email addresses.
- `passkey` binds each credential to its user.
- `security`'s `getClientIp` follows Express trust-proxy semantics.
- The oauth2 server restricts dynamic client registration and scopes.
