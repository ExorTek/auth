# @exortek/opaque

## 1.0.0

### Major Changes

- 227abe3: Initial release. Opaque reference tokens for Node.js 22+ — random, unstructured tokens with no embedded
  payload.

  - `generate` / `create` / `verify` / `revoke` / `mask`
  - RFC 7662 token introspection and RFC 7009 token revocation HTTP handlers, framework-agnostic (raw Node, Express,
    Fastify)
  - `memoryStore`, `redisStore`, and `customStore` (validates a user-supplied `OpaqueStore` implementation at
    construction time)
  - Zero non-`@exortek/*` runtime dependencies
