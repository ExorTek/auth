# @exortek/paseto

## 1.1.0

### Minor Changes

- 89aea87: Validate custom store implementations at construction time. `createStore('custom', { impl })` previously
  accepted any object and returned it verbatim, so a store missing a required method surfaced only later as a
  `TypeError` deep inside a token operation. It now asserts the impl exposes the core registry contract — `add`, `has`,
  `get`, `delete`, `deleteAll` — and throws `INVALID_ARGUMENT` immediately when one is missing (`markUsed` stays
  optional, since only refresh-token rotation calls it).

  Behaviour change: an incomplete custom store that happened to work — because the missing method was never exercised —
  is now rejected up front. Complete implementations are unaffected and are still returned verbatim (no wrapping).

### Patch Changes

- 89aea87: Ship self-contained TypeScript declarations. Every package's emitted `.d.ts` referenced `@exortek/shared`
  (e.g. `import { BaseError } from '@exortek/shared/errors'`), but `@exortek/shared` is a private, never-published
  workspace package that is inlined into each bundle at build time. A TypeScript consumer therefore hit
  `Cannot find module '@exortek/shared/…'` (with `skipLibCheck` off) or silently degraded error-class types like
  `ApiKeyError` — losing its constructor signature and `.code` / `.message` — with `skipLibCheck` on.

  The build now runs a declaration-bundling pass (`rollup-plugin-dts`) after `tsc`, flattening each entry's `.d.ts` and
  inlining the `@exortek/shared` types so the shipped declarations are fully self-contained. Runtime deps and `node:*`
  stay external. No runtime or API change — types only.

## 1.0.1

### Patch Changes

- b72abf8: Fix refresh-family revocation against node-redis v6.

  The Redis store walked the keyspace with `SCAN`, seeding the cursor as a number on the node-redis branch. node-redis
  typed cursors as numbers through v5 but requires a string from v6 onward, and the declared peer range
  (`redis >=4.0.0`) admits v6 — so `deleteAll`, and therefore the family revocation that runs on detected refresh-token
  reuse, failed there. The cursor is now a string for both clients, which Redis accepts either way.

- b9e0647: Publish only the package-root README, CHANGELOG and LICENSE.

  The `files` list matched those names at any depth rather than just the root, so a nested document was published
  alongside them — `@exortek/oauth2` shipped its `examples/README.md`. The entries are now anchored to the package root.

- 0a94f13: Smaller bundles — the internal argument-guard helpers are now tree-shakeable.

  Each package bundles the guard helpers it uses. They were previously built as one object holding all fourteen, which a
  bundler cannot take apart, so every package shipped all of them regardless of how many it called. They are now
  individually importable, and each package pulls in only what it uses.

  No API change: the errors, codes and messages raised by argument validation are identical. Published bundles shrink by
  roughly 7-18% depending on the package.

## 1.0.0

### Major Changes

- 9e1eb27: Initial release of `@exortek/paseto` — Platform-Agnostic Security Tokens (PASETO v4) for Node.js 22+.

  - `v4.local` — symmetric authenticated encryption (XChaCha20 + keyed BLAKE2b, encrypt-then-MAC) via `encrypt` /
    `decrypt`.
  - `v4.public` — Ed25519 signatures via `sign` / `verify`.
  - The token's `vN.purpose.` prefix binds the primitive set — there is no negotiable `alg` header, so JWT-style
    algorithm-confusion attacks are structurally impossible.
  - Registered claims as ISO 8601 datetimes (`exp` / `nbf` / `iat`) plus `iss` / `sub` / `aud`, with `clockTolerance`;
    footers and implicit assertions are authenticated.
  - `generateKey` / `generateKeyPair`; raw keys interoperate with the official PASETO wire format and Node `KeyObject`s.
  - `decode` — read a token's version / purpose / footer without a key (for `kid`-based key selection); the payload is
    never exposed unverified. Decoders reject tokens over `maxTokenSize` (default 8192 bytes) with `TOKEN_TOO_LARGE`.
  - Token-pair layer (`@exortek/paseto/token-pair`) — access + refresh with RFC 6749 §10.4 reuse detection over a
    pluggable store (`@exortek/paseto/stores`: memory, redis, custom); the access token purpose (`local` / `public`) is
    the caller's choice.
  - Verified byte-for-byte against the official PASETO v4 test vectors. Zero runtime dependencies; BLAKE2b (keyed,
    variable-length) and HChaCha20 are vendored because `node:crypto` does not expose them.
