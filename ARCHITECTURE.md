# Architecture

`@exortek/auth` is a **framework-agnostic, server-only authentication toolkit
for Node.js 22+**, structured as **20 focused packages** under one npm scope.
This document describes the design decisions that shape the whole codebase.
Which packages are currently on npm lives in [`README.md`](./README.md); this
document is about *why the shape is the shape*.

## Positioning

A modern successor to Passport.js. The problems this repository sets out to
solve, in one sentence each:

- **Passport's ecosystem is scattered.** Hundreds of strategies, mismatched
  APIs, unmaintained corners. We ship one scope, one API family.
- **Modern JOSE is table stakes.** `jose` is excellent but runtime-agnostic
  and JOSE-only. We want a JOSE stack that plugs into the same server-only
  toolkit as our session, password, and CSRF layers.
- **Cryptographic footguns are library defaults.** `alg: 'none'` acceptance,
  optional algorithm allowlists, symmetric-secret alg confusion,
  weak-hash-by-default. We refuse them by construction, not by config.
- **The Node standard library is enough.** `node:crypto` covers everything
  we need up to the post-quantum transition. Runtime dependencies are the
  exception, not the rule.

## Design principles

These are the invariants — expect PRs that violate them to be rejected.

### 1. Zero runtime dependencies

Every package depends on `node:crypto` and its declared peer dependencies —
nothing else, with no external-dependency exceptions.

### 2. Fully standalone packages (with sanctioned exceptions)

**Leaf packages do not import from another `@exortek/*` package at runtime.**
Utility duplication (a `base64url` helper in every JOSE package, an
`ErrorCode` enum per package) is accepted deliberately, and the private
`@exortek/shared` workspace is **bundled** into each package's `dist` rather
than published — so a user who installs a leaf package pulls no workspace
peers.

The sanctioned exceptions are packages that compose the published stack and
cannot reasonably re-bundle it:

- `@exortek/session` imports `seal` / `unseal` / `CryptoError` from
  `@exortek/crypto`.
- `@exortek/jwks` imports `@exortek/jwk`.
- `@exortek/oauth2` composes the JOSE stack — it declares `@exortek/jwt`,
  `@exortek/jwks`, `@exortek/jwk`, `@exortek/jws`, `@exortek/jwe`, and
  `@exortek/paseto` as runtime dependencies. Bundling them would duplicate
  class identities (a bundled `JwtError` would not be `instanceof` a
  consumer's own `@exortek/jwt`) and bloat every entry, so they are
  externalised and declared instead.

Each such package declares those `@exortek/*` packages in its `package.json`,
so installing it pulls them with it — call this out to anyone marketing "zero
dependencies" downstream. Everything a package uses from the private
`@exortek/shared` is still bundled, so no unpublished package is ever a
runtime import.

Every other shipped package (`crypto`, `otp`, `password`, `security`, `jwk`,
`jws`, `jwt`, `jwe`, `paseto` at time of writing) is fully standalone at
runtime.

The dependency graph below tells you the *semantic* order, not the runtime
import graph. It is preserved so package authors know which package is
allowed to know about which concept.

### 3. Server-only

Every package targets Node.js. No browser code, no `crypto.subtle`
polyfills, no `window` / `document` references, no `/client` subpaths.

For protocols with an inherent browser side (WebAuthn, OAuth2
SPA / PKCE, OPAQUE), we verify server-side and point users at a maintained
companion library — see the "Server-only" section of [`AGENTS.md`](./AGENTS.md).

### 4. Explicit over implicit

Defaults choose safety over ergonomics. `alg` is always required — there is
no "guess from the key" or "default to HS256". Every failure surfaces with
a granular `ErrorCode` you can branch on. Nothing runs behind an environment
variable.

### 5. Pure JavaScript with JSDoc types

The codebase is `.js`, not `.ts`. `tsc --emitDeclarationOnly` generates
`.d.ts` from JSDoc during build. Consumers get full IDE hints without a
TypeScript toolchain in `dependencies`.

### 6. RFC test vectors are pinned

Where a specification publishes reference vectors (RFC 4226 §5.4, RFC 6238
§B, RFC 7638 §3.1, RFC 7515 Appendix A), we hard-code them in tests. They
are the canary for spec-compliance regressions.

## The 20-package stack

Numbers reflect *dependency order* — a lower number never imports from a
higher one, so packages can be adopted incrementally. The current shipping
status lives in [`README.md`](./README.md).

Status legend: ✅ shipped to npm · 🛠 on disk, pre-release · ⏳ planned.

| #  | Package                | Status | Responsibility                                                                     |
|:--:|------------------------|:------:|------------------------------------------------------------------------------------|
| 01 | `@exortek/crypto`      |   ✅   | Primitives — hash, HMAC, KDFs, cipher, sign, seal, encode, CSPRNG                   |
| 02 | `@exortek/password`    |   ✅   | Argon2id / scrypt / bcrypt / PBKDF2 + strength / pepper / history / HIBP           |
| 03 | `@exortek/otp`         |   ✅   | RFC 4226 HOTP + RFC 6238 TOTP, backup codes, `otpauth://` provisioning URI          |
| 04 | `@exortek/challenge`   |   ✅   | HMAC-signed multi-step flow tokens (userId · method · step) with opt-in single-use  |
| 05 | `@exortek/jwk`         |   ✅   | JWK — generate, import, export, thumbprint, per RFC 7517 / 7638 / 8037 / 9278       |
| 06 | `@exortek/jws`         |   ✅   | JWS — sign / verify / detached / b64:false / JSON serialisation per RFC 7515 / 7797  |
| 07 | `@exortek/jwt`         |   ✅   | JWT — sign / verify with algorithm allowlists + claims validation per RFC 7519      |
| 08 | `@exortek/jwe`         |   ✅   | JWE — RSA-OAEP, ECDH-ES, A256KW, dir per RFC 7516                                    |
| 09 | `@exortek/jwks`        |   ✅   | JWKS URI fetching, caching, `kid` rotation per RFC 7517 §5                           |
| 10 | `@exortek/session`     |   ✅   | Sealed-cookie sessions, rotation, revocation, sudo mode, Redis pub/sub              |
| 11 | `@exortek/security`    |   ✅   | CSRF, rate-limit, helmet-style headers, CORS, safe-redirect, defensive HTTP helpers  |
| 12 | `@exortek/ua`          |   ✅   | User-Agent parsing, device/browser/bot detection, Client Hints, fingerprinting      |
| 13 | `@exortek/apikey`      |   ✅   | Prefixed API keys (`sk_live_id_secret`), HMAC-SHA256 storage, scopes, middleware    |
| 14 | `@exortek/magic-link`  |   ✅   | Passwordless email-link auth — signed short-lived tokens with single-use consume    |
| 15 | `@exortek/passkey`     |   ✅   | WebAuthn Level 3 / FIDO2 server — all seven attestation formats + MDS3 + AAGUID   |
| 16 | `@exortek/opaque`      |   ✅   | Opaque reference tokens, RFC 7662 introspection + RFC 7009 revocation                |
| 17 | `@exortek/paseto`      |   ✅   | PASETO v4 — `v4.local` (XChaCha20 + keyed BLAKE2b) + `v4.public` (Ed25519), no `alg` header |
| 18 | `@exortek/oauth2`      |   ✅   | OAuth 2.1 — RP flow + provider presets + full authorization server (DPoP · PAR · JAR/JARM · device · token-exchange · dynamic registration · opt-in OIDC id_token · FAPI) |
| 19 | `@exortek/oidc`        |   ⏳   | OpenID Connect on top of `@exortek/oauth2`                                          |
| 20 | `@exortek/auth`        |   ⏳   | Umbrella — re-exports every package above                                          |

Not versioned in this table: `@exortek/shared` — internal consolidation
workspace (see `PLAN.md`), not published on its own.

## Dependency layering

```
crypto
   │
   ├─── jwk ─── jws ─── jwt ─── jwe
   │                     │
   │                     └── jwks
   │
   ├─── opaque, paseto, password, otp
   │
   ├─── magic-link, passkey, session, ua
   │
   ├─── security (csrf, rate-limit, headers, cors, redirect)
   │
   └─── oauth2 ─── oidc

otp    → challenge
apikey → security/rate-limit
```

The umbrella `@exortek/auth` re-exports every package. Individual packages
are also independently consumable.

## Per-package layout

Every package follows the same shape:

```
packages/<name>/
├── src/
│   ├── index.js              # public entrypoint — named exports + namespace object
│   ├── <feature>.js          # public modules (one per subpath export)
│   └── internal/*.js         # helpers not part of the public API
├── tests/*.test.js           # tests directory (NOT colocated in src/), run via `node --test`
├── rollup.config.js          # thin call into rollup.config.base.js
├── tsconfig.json             # extends ../../tsconfig.base.json
├── package.json              # per-subpath `exports`, `files`, `scripts`
├── LICENSE                   # MIT — copied from a sibling
├── README.md                 # public docs
└── CHANGELOG.md              # generated by Changesets on release
```

- **Dual output.** `dist/<name>.mjs` (ESM) + `dist/<name>.cjs` (CJS) per
  subpath.
- **JSDoc → `.d.ts`.** `tsc --emitDeclarationOnly` emits declarations, then a
  `rollup-plugin-dts` pass flattens each entry into one self-contained file —
  inlining the private `@exortek/shared` types (see below) so the shipped
  declarations never reference the unpublished workspace package.
- **Tests live in `tests/`**, run through Node's native `node --test` runner.
  No Jest / Mocha / Vitest.

Packages that ship subpath exports use one rollup input/output pair per
subpath. Existing examples: `@exortek/jwk` (`./generate`, `./import`,
`./export`, `./thumbprint`, `./validate`), `@exortek/jws` (`./sign`,
`./verify`, `./decode`, `./json`).

## Internal `@exortek/shared` layer

`@exortek/shared` is a `private`, never-published workspace package. Every
`@exortek/*` package imports from it (`@exortek/shared/predicates`,
`@exortek/shared/asserts`, …) but declares it nowhere: rollup **inlines** its
source into each package's `dist` at build time (Design principle 2), so a
standalone install pulls no `shared` peer. Rules to respect:

- Never "fix" the missing `dependencies` entry — it would break the
  standalone-install guarantee.
- Never publish `shared`.
- It emits no `.d.ts` of its own. So consumers don't inherit a dangling
  `import … from '@exortek/shared/*'` in their types, the declaration-bundling
  pass (see "Per-package layout") inlines `shared`'s JSDoc-derived types into
  each package's own `.d.ts`.

### Store primitives (family factories)

Stateful packages (jwt, paseto, apikey, magic-link, opaque, session, challenge,
security, oauth2) each need a memory + Redis + custom backing store. Instead of
re-implementing that per package, `shared` ships one factory per **store
family**; a package binds it once and layers its domain methods on top:

- **`record-store`** — indexed record CRUD + secondary owner-index (apikey,
  magic-link, oauth2 refresh family).
- **`registry-store`** — blacklist / refresh-token registry with atomic
  `markUsed` (jwt, paseto).
- **`incr-store`** — atomic TTL counter for replay guards / rate limits
  (challenge, magic-link, security).
- **`custom-store`** — `createCustomStoreValidator` / `assertStoreShape`:
  validate a caller-supplied store and promote its sync methods to the async
  interface.
- **`redis-helpers`** — the single ioredis / node-redis / Upstash dialect layer
  (`detectDialect`, `evalScript`, `setWithTTL`); every Redis store dispatches
  through it, so a driver quirk is fixed in one place.

Adding a store means composing these, not re-writing memory/Redis/dialect
plumbing. Genuinely different shapes (session's anonymous-first eviction,
security's bucket compare-and-set) stay in their package — shared owns the
mechanics, the package owns its domain.

## Modern JOSE conventions

The JOSE packages (`jwk`, `jws`, `jwt`, `jwe`, `jwks`) diverge from `jose`
the library in a handful of deliberate ways. These are the reasons the
stack exists — preserve them when extending.

1. **Algorithm allowlist is mandatory on verify.** Omitting it raises
   `MISSING_ALG_ALLOWLIST`. No default, no fallback.
2. **`alg: 'none'` is refused everywhere.** No flag, no environment
   variable, no configuration. Raises `ALGORITHM_NONE_FORBIDDEN`. Defence
   in depth: the algorithm table has no `none` entry *and* the sign /
   verify surfaces short-circuit before any lookup.
3. **`crit` is strict by default.** Unknown critical headers raise
   `CRIT_UNSUPPORTED`. Callers can opt in named extensions via
   `knownCriticalHeaders`.
4. **Key input is polymorphic.** JWK object, `KeyObject`, `Buffer` (HMAC
   only), JWK array (kid dispatch), and `async (header) => key` resolver
   functions are all first-class.
5. **Granular `ErrorCode` per package.** Branch on `err.code`, never on
   `err.message`.

## Post-quantum roadmap

**ML-DSA** (FIPS 204, signatures) and **ML-KEM** (FIPS 203, key
encapsulation) are on the roadmap for the JOSE stack. Shipping them today
would mean bundling a JS lattice-crypto implementation — a red line.

Timeline gate:

- **OpenSSL 3.5** (April 2025) added ML-DSA / ML-KEM.
- **Node 22–24** ships OpenSSL 3.0–3.4 — no `generateKeyPair('ml-dsa-65')` yet.
- **Node 25 / 26** (2026–2027) will expose them once the OpenSSL bump lands.
- **`draft-ietf-jose-pqc`** — JWK / JWS registrations with provisional
  `kty: "AKP"` — is still a draft.

When both boxes tick (Node native primitives + stable JOSE registrations),
we add `ML-DSA-{44,65,87}` and `ML-KEM-{512,768,1024}` to the same
surface. Until then, users needing PQ today can wire in
[`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum).

## Documentation surface

- **[`README.md`](./README.md)** — the public entrypoint. Ground truth for
  which packages are on npm.
- **`packages/<name>/README.md`** — per-package public docs (badges, why,
  quick start, error catalogue, highlights).
- **[`web/`](./web)** — Nextra docs site published to `auth.memet.dev`.
  Per-module deep dives per shipped package.
- **[`AGENTS.md`](./AGENTS.md)** — agent-agnostic contributor guide
  (workflows, conventions, non-goals).
- **[`SECURITY.md`](./SECURITY.md)** — vulnerability reporting +
  supported-versions matrix.
- **[`CONTRIBUTING.md`](./CONTRIBUTING.md)** — human contributor onboarding.
- **[`docs/compliance.md`](./docs/compliance.md)** — mapping onto
  NIST SP 800-63B, OWASP ASVS 4.0.3, PCI-DSS 4.0.

## RFC and standards references

Where each protocol is anchored:

| Package         | RFC / spec references                                                        |
|-----------------|------------------------------------------------------------------------------|
| `crypto`        | NIST SP 800-108 (KDF), NIST SP 800-38D (GCM), RFC 5869 (HKDF), RFC 8018 (PBKDF2), RFC 8785 (JCS) |
| `password`      | Argon2 spec (2015), NIST SP 800-63B §5.1.1, OWASP ASVS V2                     |
| `otp`           | RFC 4226 (HOTP), RFC 6238 (TOTP), Google Authenticator `otpauth://` URI spec |
| `jwk`           | RFC 7517 (JWK), RFC 7518 §6 (JWK parameters), RFC 7638 (thumbprint), RFC 8037 (OKP), RFC 8812 (secp256k1), RFC 9278 (thumbprint URI) |
| `jws`           | RFC 7515 (JWS), RFC 7518 §3 (JWA), RFC 7797 (unencoded payload), RFC 8037, RFC 8812, RFC 8725 (BCP) |
| `jwt`           | RFC 6749 §10.4 (refresh reuse), RFC 7519 (JWT), RFC 8725 (BCP), RFC 9068 (JWT profile for OAuth2) |
| `jwe`           | RFC 7516 (JWE), RFC 7518 §4–§5 (key management + content encryption), RFC 8725 (BCP) |
| `jwks`          | RFC 7517 §5 (JWK Set), OpenID Connect Discovery                                |
| `opaque`        | RFC 7662 (Token Introspection), RFC 7009 (Token Revocation)                   |
| `paseto`        | PASETO v4 (paseto.io spec), RFC 6749 §10.4 (refresh reuse), RFC 7693 (BLAKE2b) |
| `session`       | OWASP ASVS 4.0.3 V3, RFC 6265 (Cookies)                                       |
| `security`      | OWASP ASVS 4.0.3 V13 / V14, RFC 6749 §10 (OAuth2 threats), RFC 7231 §5 (HTTP) |
| `oauth2`        | OAuth 2.1 / RFC 9700 (BCP), RFC 6749, RFC 7636 (PKCE), RFC 9207 (iss), RFC 8414 (metadata), RFC 9449 (DPoP), RFC 9126 (PAR), RFC 8707 (resource), RFC 9396 (RAR), RFC 9101 (JAR/JARM), RFC 7523 / 8705 (client auth), RFC 8693 (exchange), RFC 8628 (device), RFC 7591 (dynamic registration), RFC 9068 (JWT profile), OpenID Connect Core (id_token, opt-in OP mode), FAPI 2.0 |
| `oidc`          | _(planned)_ OpenID Connect Core 1.0, OpenID Connect Discovery |
| `passkey`       | W3C WebAuthn Level 3, FIDO2 CTAP2                                             |

For deeper per-package interface tables (JSDoc typedefs, worked API
examples, migration notes) look at a shipping package alongside its
README and per-module docs on [`auth.memet.dev`](https://auth.memet.dev).
