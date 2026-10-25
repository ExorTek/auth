---
'@exortek/opaque': major
---

- Tokens are random-only with ≥ 128 bits: `ulid` and `uuid7` are refused (consecutive ULID tokens differed only in their last character), byte generators need `bytes ≥ 16`, `alphanumeric` needs `length ≥ 22`.
- `create()` requires `expiresIn` (`null` for a deliberately non-expiring token) instead of silently minting an immortal one.
- `introspectionHandler` requires an `authorize(req)` hook and answers `401 invalid_client` without it (RFC 7662 §2.1); `revocationHandler` accepts the hook optionally.
- The memory store is bounded (`maxEntries`, default 100,000).

**Migration:** switch `ulid` / `uuid7` tokens to `hex` / `base64url` / `base58` / `crockford` / `uuid4`, pass `expiresIn` to `create()`, and give `introspectionHandler` an `authorize` hook.
