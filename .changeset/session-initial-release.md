---
'@exortek/session': major
---

Initial release of `@exortek/session`.

Sealed-cookie session manager built on `@exortek/crypto.seal`. Ships
every session concern a backend actually needs, opt-in via config
flags so callers pay only for what they use.

**Core (default on):**

- Sealed cookie via `crypto.seal` — stateless verify hot-path
- Cookie + `Authorization: Bearer` header extraction
- Absolute + rolling idle TTL
- Multi-secret rotation
- In-process memory store with LRU eviction and background sweep
- Per-request cache — 3 `verify(req)` calls → 1 decrypt
- `issue` / `verify` / `rotate` / `touch` / `revoke` / `revokeById` /
  `revokeAllForUser` / `revokeAllExceptCurrent` / `listActive`
- `deriveCsrfToken` / `verifyCsrfToken` — session-bound synchroniser tokens
- `SessionError` + 14 stable error codes

**Opt-in features:**

- **Anonymous / guest sessions** with `anonymous: true`
- **Concurrent session limit** — 3 devices max, oldest kicked
- **Fingerprint binding** — `bindTo: ['ip', 'ua']`; mismatch → hard revoke
- **Impersonation** — admin-as-user with `impersonatedBy` audit trail
- **Device labels** — `iPhone 14 · Chrome` from the UA
- **Session events** — `onIssue`, `onVerify`, `onRotate`, `onRevoke`,
  `onDeny`, `onSuspicious` callbacks
- **Suspicious activity detection** — IP change flagging
- **Sudo mode / step-up authentication** — `requireFreshAuth` + `markFresh`
- **Remember-me** — doubles the absolute TTL on issue

**Subpaths:**

- `@exortek/session/stores/redis` — Redis session store with
  optional `publishRevocations: true` pub/sub for cross-worker cache
  invalidation. Works with `ioredis` or `node-redis@4+`.
- `@exortek/session/trusted-device` — separate long-lived
  HMAC-authenticated cookie for "remember this device" 2FA skip.
  Multi-secret rotation.
- `@exortek/session/fastify` — plugin with `req.session` +
  `req.sessions` + `reply.setSessionCookie` / `reply.clearSessionCookie`
- `@exortek/session/express` — middleware with the same shape
- `@exortek/session/hono` — middleware setting `c.get('session')`,
  `c.get('sessions')`
- `@exortek/session/elysia` — plugin using `derive` to inject
  `session` + `sessions` onto the context

**Compliance impact** — the following OWASP ASVS V3 rows on
`docs/compliance.md` move from 🟡 to ✅:

- V3.2 Session token via CSPRNG
- V3.4 Secure / HttpOnly / SameSite cookie flags
- V3.5 `__Host-` prefix binding
- V3.7 Server-side invalidation on logout

**144 unit tests** — errors, cookie, header, token round-trip,
memory + Redis stores, manager (issue/verify/revoke/rotate/touch),
sudo mode, fingerprint, device labels, impersonation, events,
suspicious activity, CSRF derivation, trusted-device, and the four
framework adapters via mocks.
