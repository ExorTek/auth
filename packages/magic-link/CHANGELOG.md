# @exortek/magic-link

## 2.1.2

### Patch Changes

- 99962b6: Fix two defects in the Redis store's `consume`.

  `consume` and `revokeByEmail` issued their Lua call in the `ioredis` argument form for every client, so both failed
  outright against node-redis — despite the module documenting node-redis as a supported client. They now go through the
  shared dialect-aware helper.

  Separately, and on every client: the script treated a record whose `consumedAt` was explicitly `null` as already
  consumed, because Redis's cjson decodes a JSON null to a truthy value. A link stored that way could never be redeemed.
  `create()` omits the field, so the default flow was unaffected, but `consumedAt` is part of the documented record
  shape and normalising an absent field to `null` is a common round-trip.

- b9e0647: Publish only the package-root README, CHANGELOG and LICENSE.

  The `files` list matched those names at any depth rather than just the root, so a nested document was published
  alongside them — `@exortek/oauth2` shipped its `examples/README.md`. The entries are now anchored to the package root.

- 0a94f13: Smaller bundles — the internal argument-guard helpers are now tree-shakeable.

  Each package bundles the guard helpers it uses. They were previously built as one object holding all fourteen, which a
  bundler cannot take apart, so every package shipped all of them regardless of how many it called. They are now
  individually importable, and each package pulls in only what it uses.

  No API change: the errors, codes and messages raised by argument validation are identical. Published bundles shrink by
  roughly 7-18% depending on the package.

- 828f4ae: Fix Redis TTL and Lua handling so both supported clients behave the same.

  The internal helper that writes a key with an expiry tried the `ioredis` argument form and fell back only if it threw.
  node-redis does not throw on that form — it accepts the call and stores the key with **no expiry at all**, so the
  fallback never ran and the TTL was silently dropped. Anything given a lifetime through this path never expired on
  node-redis: OAuth 2 authorization codes, PAR request URIs and device codes among them.

  The shared counter behind `challenge` and `magic-link` rate limiting had the same problem in its Lua call, where it
  surfaced as a failure rather than silence, and let the driver's own error escape instead of the package's.

  Both now dispatch on the detected client, and counter failures are reported as the calling package's error type with a
  `code` you can branch on.

## 2.1.1

### Patch Changes

- e53ae64: Fix polynomial-ReDoS (quadratic regex backtracking) surfaced by CodeQL, plus small code-quality fixes.
  Bundled `@exortek/shared` utilities (base32, base64, duration) are inlined into the packages listed above, so each
  ships the fix.

  - Replace `/=+$/` trailing-padding strips (base32 / base64 decode, OTP provisioning URI) with linear scans —
    `"=".repeat(n) + "x"` was O(n²).
  - Rework the duration parser regex so surrounding whitespace can no longer cause O(n²) matching (trim first, single
    interior `\s*`).
  - Strip trailing spaces/dots in filename sanitisation with a linear scan — upload filenames are attacker-controlled.
  - Cap email length before the regex in magic-link.
  - Thread the JWT decode label into error messages (removes dead arguments and gives failures which segment broke).
  - Drop a duplicate character in a UA browser-detection regex character class.

  DoS-hardening and hygiene only — no API or behavioural change for valid input.

## 2.1.0

### Minor Changes

- c587ef8: Add `customStore(impl)` — wrap your own `MagicLinkStore` implementation with validation (fails at
  construction time if `put`/`getById`/`consume` are missing) and transparent sync/async wrapping.
  `incrRate`/`listByEmail`/`revokeByEmail` are passed through only when your implementation provides them.

### Patch Changes

- 40fc707: Docs: document the previously-undocumented `listPendingForEmail` and `revokeAllForEmail` functions; align
  README structure (badges, `Why`, `Highlights`, `Links`) with the rest of the `@exortek/*` packages.

## 2.0.1

### Patch Changes

- 689cf87: Remove workspace-only `devDependencies` from published package.json — `@exortek/shared` no longer appears as
  `"0.0.0"` on the npm registry.

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
