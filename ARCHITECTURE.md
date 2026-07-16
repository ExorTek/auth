# Architecture

`@exortek/auth` is a **framework-agnostic, server-only authentication toolkit
for Node.js 22+**, structured as **22 focused packages** under one npm scope.
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
nothing else. The single planned external exception is `@exortek/web3-evm`,
which will use `ethereum-cryptography`.

### 2. Fully standalone packages (with one sanctioned exception)

**New packages do not import from another `@exortek/*` package at runtime.**
Utility duplication (a `base64url` helper in every JOSE package, an
`ErrorCode` enum per package) is accepted deliberately. A user who installs
a single package pulls no workspace peers.

The one sanctioned exception is `@exortek/session`, which imports `seal`,
`unseal`, and `CryptoError` from `@exortek/crypto`. It was written before
the standalone policy was formalised and the sealed-cookie primitive was
too surface-heavy to duplicate. Session's `package.json` declares
`@exortek/crypto` as a runtime dependency, and installing session pulls
crypto with it — call this out to anyone marketing "zero dependencies"
downstream.

Every other shipped package (`crypto`, `otp`, `password`, `security`, `jwk`,
`jws` at time of writing) is fully standalone at runtime.

The dependency graph below tells you the *semantic* order, not the runtime
import graph. It is preserved so package authors know which package is
allowed to know about which concept.

### 3. Server-only

Every package targets Node.js. No browser code, no `crypto.subtle`
polyfills, no `window` / `document` references, no `/client` subpaths.

For protocols with an inherent browser side (WebAuthn, SIWE, SIWS, OAuth2
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

## The 22-package stack

Numbers reflect *dependency order* — a lower number never imports from a
higher one, so packages can be adopted incrementally. The current shipping
status lives in [`README.md`](./README.md).

| #  | Package                | Responsibility                                                                     |
|:--:|------------------------|------------------------------------------------------------------------------------|
| 01 | `@exortek/crypto`      | Primitives — hash, HMAC, KDFs, cipher, sign, seal, encode, CSPRNG                   |
| 02 | `@exortek/password`    | Argon2id / scrypt / bcrypt / PBKDF2 + strength / pepper / history / HIBP           |
| 03 | `@exortek/otp`         | RFC 4226 HOTP + RFC 6238 TOTP, backup codes, `otpauth://` provisioning URI          |
| 04 | `@exortek/challenge`   | E-mail / SMS one-time code storage + verification                                   |
| 05 | `@exortek/jwk`         | JWK — generate, import, export, thumbprint, per RFC 7517 / 7638 / 8037 / 9278       |
| 06 | `@exortek/jws`         | JWS — sign / verify / detached / b64:false / JSON serialisation per RFC 7515 / 7797  |
| 07 | `@exortek/jwt`         | JWT — sign / verify with algorithm allowlists + claims validation per RFC 7519      |
| 08 | `@exortek/jwe`         | JWE — RSA-OAEP, ECDH-ES, A256KW, dir per RFC 7516                                    |
| 09 | `@exortek/jwks`        | JWKS URI fetching, caching, `kid` rotation per RFC 7517 §5                           |
| 10 | `@exortek/session`     | Sealed-cookie sessions, rotation, revocation, sudo mode, Redis pub/sub              |
| 11 | `@exortek/security`    | CSRF, rate-limit, helmet-style headers, CORS, safe-redirect, defensive HTTP helpers  |
| 12 | `@exortek/device`      | Device fingerprinting, trusted-device tokens                                        |
| 13 | `@exortek/apikey`      | Prefixed API keys (`sk_live_…`) with built-in rate-limit                            |
| 14 | `@exortek/magic-link`  | Passwordless e-mail / SMS link tokens                                               |
| 15 | `@exortek/passkey`     | WebAuthn / FIDO2 server verification (`/server` only; browser via community lib)    |
| 16 | `@exortek/opaque`      | OPAQUE aPAKE — zero-knowledge password authentication                               |
| 17 | `@exortek/paseto`      | PASETO v4 (`local` / `public`)                                                     |
| 18 | `@exortek/oauth2`      | OAuth 2.1 client (PKCE) + provider presets                                          |
| 19 | `@exortek/oidc`        | OpenID Connect on top of `@exortek/oauth2`                                          |
| 20 | `@exortek/web3-evm`    | SIWE — Sign-In With Ethereum                                                       |
| 21 | `@exortek/web3-solana` | SIWS — Sign-In With Solana                                                         |
| 22 | `@exortek/auth`        | Umbrella — re-exports every package above                                          |

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
   ├─── magic-link, passkey, session, device
   │
   ├─── security (csrf, rate-limit, headers, cors, redirect)
   │
   ├─── oauth2 ─── oidc
   │
   └─── web3-evm, web3-solana

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
- **JSDoc → `.d.ts`.** `tsc --emitDeclarationOnly` emits declaration files at
  build time.
- **Tests live in `tests/`**, run through Node's native `node --test` runner.
  No Jest / Mocha / Vitest.

Packages that ship subpath exports use one rollup input/output pair per
subpath. Existing examples: `@exortek/jwk` (`./generate`, `./import`,
`./export`, `./thumbprint`, `./validate`), `@exortek/jws` (`./sign`,
`./verify`, `./decode`, `./json`).

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
| `crypto`        | NIST SP 800-108 (KDF), NIST SP 800-38D (GCM), RFC 5869 (HKDF), RFC 8018 (PBKDF2) |
| `password`      | Argon2 spec (2015), NIST SP 800-63B §5.1.1, OWASP ASVS V2                     |
| `otp`           | RFC 4226 (HOTP), RFC 6238 (TOTP), Google Authenticator `otpauth://` URI spec |
| `jwk`           | RFC 7517 (JWK), RFC 7518 §6 (JWK parameters), RFC 7638 (thumbprint), RFC 8037 (OKP), RFC 8812 (secp256k1), RFC 9278 (thumbprint URI) |
| `jws`           | RFC 7515 (JWS), RFC 7518 §3 (JWA), RFC 7797 (unencoded payload), RFC 8037, RFC 8812, RFC 8725 (BCP) |
| `jwt`           | RFC 7519 (JWT), RFC 8725 (BCP), RFC 9068 (JWT profile for OAuth2)              |
| `jwe`           | RFC 7516 (JWE), RFC 7518 §4 (encryption algorithms), RFC 8037 (X25519 / X448)  |
| `jwks`          | RFC 7517 §5 (JWK Set), OpenID Connect Discovery                                |
| `opaque`        | draft-irtf-cfrg-opaque                                                        |
| `paseto`        | PASETO v4 spec                                                                |
| `session`       | OWASP ASVS 4.0.3 V3, RFC 6265 (Cookies)                                       |
| `security`      | OWASP ASVS 4.0.3 V13 / V14, RFC 6749 §10 (OAuth2 threats), RFC 7231 §5 (HTTP) |
| `oauth2`        | RFC 6749, RFC 7636 (PKCE), RFC 9126 (PAR), RFC 8414 (metadata), RFC 8628 (device)|
| `oidc`          | OpenID Connect Core 1.0, OpenID Connect Discovery                              |
| `passkey`       | W3C WebAuthn Level 3, FIDO2 CTAP2                                             |
| `web3-evm`      | EIP-4361 (SIWE)                                                              |
| `web3-solana`   | SIWS spec                                                                    |

For deeper per-package interface tables (JSDoc typedefs, worked API
examples, migration notes) look at a shipping package alongside its
README and per-module docs on [`auth.memet.dev`](https://auth.memet.dev).
