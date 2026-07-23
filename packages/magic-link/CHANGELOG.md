# @exortek/magic-link

## 2.0.0

### Initial release

- **`createMagicLink(options)`** — mint an HMAC-signed short-lived token and the URL to embed in a "sign in" email. The
  package deliberately does not send emails — you keep control of the mail driver (Sendgrid / Resend / SES / SMTP).
- **`verifyMagicLink(token, options)`** — HMAC-verify + expiry + single-use consume in one call. Never throws on a bad
  token; returns `{ valid: true, email, redirectTo?, metadata? }` or `{ valid: false, reason }` across a 9-case reason
  catalogue.
- **`consume: true` by default** — a magic link is one-shot. Flip to `false` for a two-phase preview → confirm flow.
- **Email hashing** — `hashEmail: true` by default. The token payload carries `SHA-256(secret ‖ email)` so
  `expectedEmail` can short-circuit a wrong-email reject before touching the store, and a poisoned store row swapping
  the email surfaces as `email_binding_mismatch`. Turn off for a shorter token.
- **`maxPerEmail: { count, window }`** — opt-in per-email rate limit built into `create`, using the same store's
  `incrRate`. Prevents a spammer from hitting your mail budget without external rate-limit infra.
- **Configurable prefix** — default `mlink_v1`; override to brand the wire format (`login_v1`, `myapp_v1`, …).
- **`listPendingForEmail(email)`** / **`revokeAllForEmail(email)`** — for "resend last email" flows and
  account-lifecycle events (password reset, deletion).
- **Stores:** `memoryStore()` (Map with deep-clone semantics) and `redisStore(client, options?)` (JSON blob + SADD-set
  per email + Lua CAS `consume` + Lua INCR-with-PEXPIRE `incrRate`) under `@exortek/magic-link/stores`.
- **Errors:** `MagicLinkError` + `ErrorCode` catalogue (`INVALID_ARGUMENT` / `INVALID_SECRET` / `INVALID_PREFIX` /
  `RATE_LIMITED` / `STORE_ERROR`). Expected verify failures return `{ valid: false, reason }`, not exceptions.
