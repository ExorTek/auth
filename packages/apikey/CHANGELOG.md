# @exortek/apikey

## 1.0.0

### Initial release

- **`createApiKey(options)`** — mint a Stripe-style 3-segment token
  `<prefix>_<id>_<secret>` (base32-crockford, no ambiguous glyphs).
  Stores an HMAC-SHA256 hash of the secret plus a plaintext id for
  O(1) lookup. Optional peppers (newest-first array, each ≥16 bytes)
  turn a stolen DB into a non-crackable artifact.
- **`verifyApiKey(rawKey, options)`** — parse, look up by id, timing-safe
  hash compare, expiry / revocation / scope enforcement. Returns
  `{ valid: true, userId, scopes, id, prefix, name?, environment?, metadata?, needsRehash? }`
  or `{ valid: false, reason }` — never throws on a bad key.
- **Scopes:** `hasAll` / `hasAny` / `covers` with `*` super wildcard and
  `namespace:*` suffix wildcard.
- **Pepper rotation:** verify against every pepper, mint with the
  newest; `needsRehash: true` in the verify result signals the secret
  matched an older pepper so `rehashApiKey` can silently migrate
  storage.
- **`revokeApiKey`** (by key or id), **`revokeAllForUser`**,
  **`listApiKeys`** (sorted most-recently-used first).
- **`mask(key)`** log-safe display, **`parseApiKey(key)`** unverified
  segment extraction.
- **Stores:** `memoryStore()` and `redisStore(client, options?)` under
  the `@exortek/apikey/stores` subpath. Standard CRUD (`put` /
  `getById` / `update` / `revoke` / `revokeAllForUser` / `listByUser`)
  — bring your own by implementing the interface.
- **Middleware:** Express (`@exortek/apikey/middleware/express`) and
  Fastify (`@exortek/apikey/middleware/fastify`) adapters over a
  shared `middleware/core.js` — `Authorization: Bearer <key>` by
  default, configurable header + raw scheme + opt-in query-param
  fallback. Attaches the verify result to `req.apiKey`.
- **Errors:** `ApiKeyError` + `ErrorCode` catalogue
  (`INVALID_ARGUMENT` / `INVALID_PREFIX` / `INVALID_PEPPER` /
  `STORE_ERROR`). Expected verify failures surface as
  `{ valid: false, reason }`, not exceptions.
