# @exortek/challenge

## 1.1.2

### Patch Changes

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

## 1.1.1

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

## 1.1.0

### Minor Changes

- 76f8f83: Add `customStore(impl)` — wrap your own `IncrStore` implementation with validation (fails at construction
  time if `incr` is missing) and transparent sync/async wrapping.

### Patch Changes

- 40fc707: Docs: document the previously-missing `prefix` option on `verifyChallenge` (it was already documented on
  `createChallenge`); align README structure (badges, `Why`, `Highlights`, `Links`) with the rest of the `@exortek/*`
  packages.

## 1.0.2

### Patch Changes

- 689cf87: Remove workspace-only `devDependencies` from published package.json — `@exortek/shared` no longer appears as
  `"0.0.0"` on the npm registry.

## 1.0.1

### Patch Changes

- 31223e4: Consolidate duplicated store internals into @exortek/shared utilities (redis-helpers, incr-store,
  record-store). No public API changes.

  apikey: fix Redis store race condition where a concurrent update() could silently un-revoke a key — revocations now
  use a tombstone key that update() never touches.

  apikey: fix memory store put() storing by reference instead of copying — now consistent with getById()'s copy-on-read
  contract.

## 1.0.0

### Initial release

- **`createChallenge(options)`** — issue an HMAC-signed challenge token carrying `userId` / `method` / `step` /
  `nextStep` / `metadata` across a multi-step auth flow. Optional `ipBinding` stamps the origin IP into the payload;
  optional `singleUse` marks the token for one-shot consumption via a caller-supplied store.
- **`verifyChallenge(token, options)`** — HMAC-verify, expiry-check, and optionally match `expectedUserId` /
  `expectedMethod` / `expectedStep` / `expectedNextStep`, plus IP match when the token was IP-bound. Returns
  `{ valid: true, payload }` on success or `{ valid: false, reason }` on any expected failure; never throws on bad
  tokens, only on programmer errors.
- **Stores** — ships `memoryStore()` (single-node / dev, LRU + TTL sweep) and `redisStore(client)` (cluster-safe, single
  Lua round-trip per verify) under the `@exortek/challenge/stores` subpath. Any object exposing
  `incr(key, ttlMs) → { count }` also works — e.g. `@exortek/security`'s rate-limit stores.
- **Token format:** `<prefix>.<base64url(payload)>.<base64url(hmac)>` — deliberately not a JWT so the two token families
  cannot be confused at a call site. Prefix defaults to `chall_v1`; callers can override via `options.prefix` (e.g.
  `'server_challenge'`, `'myapp_v1'`) to brand the wire format for their service. Must match `/^[A-Za-z0-9_-]{1,32}$/`,
  and the same prefix must be used at create and verify time.
- **Errors:** stable `ErrorCode.INVALID_ARGUMENT` / `ErrorCode.INVALID_SECRET` codes on the `ChallengeError` class.
