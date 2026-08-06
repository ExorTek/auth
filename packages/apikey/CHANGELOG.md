# @exortek/apikey

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

- b1f5d6e: Add `customStore(impl)` — wrap your own `ApiKeyStore` implementation with validation (fails at construction
  time if a required method is missing) and transparent sync/async wrapping, instead of hand-assembling the interface
  yourself.

### Patch Changes

- 40fc707: Docs: add a "Rate limiting" section explaining why `@exortek/apikey` ships no built-in limiter and how to
  front the mint/verify routes with `@exortek/security`'s rate-limit (with a runnable demo in both example servers);
  document the previously-undocumented `revokeAllForUser` and `listApiKeys` functions; align README structure (badges,
  `Why`, `Highlights`, `Links`) with the rest of the `@exortek/*` packages.

## 1.0.2

### Patch Changes

- 689cf87: Remove workspace-only `devDependencies` from published package.json — `@exortek/shared` no longer appears as
  `"0.0.0"` on the npm registry.
- 689cf87: Replace `fastify-plugin` npm dependency with `@exortek/shared/fastify-plugin` — a built-in drop-in that
  covers skip-override, display-name, plugin-meta, version constraints, and encapsulate. Users no longer need to
  `npm i fastify-plugin` alongside fastify.

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

- **`createApiKey(options)`** — mint a Stripe-style 3-segment token `<prefix>_<id>_<secret>` (base32-crockford, no
  ambiguous glyphs). Stores an HMAC-SHA256 hash of the secret plus a plaintext id for O(1) lookup. Optional peppers
  (newest-first array, each ≥16 bytes) turn a stolen DB into a non-crackable artifact.
- **`verifyApiKey(rawKey, options)`** — parse, look up by id, timing-safe hash compare, expiry / revocation / scope
  enforcement. Returns `{ valid: true, userId, scopes, id, prefix, name?, environment?, metadata?, needsRehash? }` or
  `{ valid: false, reason }` — never throws on a bad key.
- **Scopes:** `hasAll` / `hasAny` / `covers` with `*` super wildcard and `namespace:*` suffix wildcard.
- **Pepper rotation:** verify against every pepper, mint with the newest; `needsRehash: true` in the verify result
  signals the secret matched an older pepper so `rehashApiKey` can silently migrate storage.
- **`revokeApiKey`** (by key or id), **`revokeAllForUser`**, **`listApiKeys`** (sorted most-recently-used first).
- **`mask(key)`** log-safe display, **`parseApiKey(key)`** unverified segment extraction.
- **Stores:** `memoryStore()` and `redisStore(client, options?)` under the `@exortek/apikey/stores` subpath. Standard
  CRUD (`put` / `getById` / `update` / `revoke` / `revokeAllForUser` / `listByUser`) — bring your own by implementing
  the interface.
- **Middleware:** Express (`@exortek/apikey/middleware/express`) and Fastify (`@exortek/apikey/middleware/fastify`)
  adapters over a shared `middleware/core.js` — `Authorization: Bearer <key>` by default, configurable header + raw
  scheme + opt-in query-param fallback. Attaches the verify result to `req.apiKey`.
- **Errors:** `ApiKeyError` + `ErrorCode` catalogue (`INVALID_ARGUMENT` / `INVALID_PREFIX` / `INVALID_PEPPER` /
  `STORE_ERROR`). Expected verify failures surface as `{ valid: false, reason }`, not exceptions.
