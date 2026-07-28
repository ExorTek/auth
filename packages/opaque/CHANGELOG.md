# @exortek/opaque

## 1.0.0

### Major Changes

- 227abe3: Initial release. Opaque reference tokens for Node.js 22+ — random, unstructured tokens with no embedded
  payload.

  - Core API: `generate` / `create` / `verify` / `revoke` / `mask`
  - Errors: `OpaqueError`, `ErrorCode`
  - HTTP handlers: `introspectionHandler` (RFC 7662), `revocationHandler` (RFC 7009), framework-agnostic (raw Node,
    Express, Fastify)
  - Subpath `@exortek/opaque/stores`: `memoryStore`, `redisStore`, `customStore` (validates a user-supplied
    `OpaqueStore` implementation at construction time)
  - Zero non-`@exortek/*` runtime dependencies
