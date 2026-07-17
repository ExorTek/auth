---
'@exortek/jwt': major
---

Initial release of `@exortek/jwt` — JSON Web Token for Node.js 22+.
**RFC 7519** (JWT core), **RFC 8725** (best current practice),
**RFC 9068** (OAuth 2.0 access-token profile),
**RFC 6749 §10.4** (refresh-token reuse-detection threat model),
**RFC 7518** (JWA algorithms), **RFC 8037** (Ed25519 / Ed448),
**RFC 8812** (`secp256k1`). Zero dependencies. Server-only.

## Surface

- **Core (root export):** `sign`, `verify`, `peek`, `decode`,
  `decodeProtectedHeader`, `JwtError`, `ErrorCode`, `jwt` namespace.
- **`@exortek/jwt/token-pair`:** `tokenPair.create / .rotate / .revoke /
  .revokeAll` with RFC 6749 §10.4 reuse detection.
- **`@exortek/jwt/stores`:** `createStore('memory' | 'redis' |
  'custom', ...)` with `interval` / `lazy` / `lru` GC strategies for
  the in-process store, native TTL for Redis (both ioredis and
  redis@4 clients auto-detected), and a `custom` factory that accepts
  the caller's own `Store` implementation.

## Algorithm matrix

HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512, ES256K,
EdDSA (Ed25519 + Ed448). **`none` refused everywhere** — no flag can
enable it. RSA modulus ≥ 2048 (RFC 7518 §3.3 / §3.5) and HMAC minimum
secret bytes (RFC 7518 §3.2) enforced across every input branch.

## Twelve differentiators

1. **`tokenPair` with reuse detection** — the killer feature; no other
   JWT lib ships this.
2. **Mandatory `alg` allowlist on verify** — `MISSING_ALG_ALLOWLIST`
   before any parsing.
3. **`alg: 'none'` refused everywhere** — dedicated
   `ALGORITHM_NONE_FORBIDDEN` code.
4. **Blacklist store** — memory + Redis + custom with three GC
   strategies.
5. **Custom-fn escape hatch on every knob** — `hashFn`, `generate`,
   `issuer` / `audience` async predicates, encoding matrix, `jwtId`
   factory.
6. **`typ` enforcement + RFC 9068 (`at+jwt`) preset.**
7. **`maxAge` — iat freshness policy** for leaked-token mitigation.
8. **`scope` validation first-class** (`requiredScopes`), reading
   `payload.scope` (RFC 8693 §4.2) or `payload.scp` (array).
9. **`peek`** — signature-verified inspection without claim checks
   (audit / logging safe path).
10. **`sign` metadata return** —
    `{ token, jti, expiresAt, issuedAt, alg, kid }`.
11. **`aud` array + `iss` array on verify** — multi-tenant SaaS native;
    RFC 7519 §4.1.3 array-form audience handled.
12. **PEM string + X.509 certificate input** —
    `fs.readFileSync('./private.pem', 'utf8')` shape works directly.

## Key input polymorphism

`KeyObject` | `Buffer` / `Uint8Array` (HMAC) | **PEM string** (private /
public / X.509 cert — dispatched on the `-----BEGIN` header) | **HMAC
secret string** (UTF-8 bytes, matching `jsonwebtoken`) | JWK object |
JWK array (kid dispatch) | `async (header) => key` resolver.

## Deliberate omissions

- Callback-style API (Promise-only)
- Synchronous `sign` / `verify`
- `ignoreExpiration` / `ignoreNotBefore` (`peek` is the safe alternative)
- `mutatePayload` (payload always immutable)
- `allowInsecureKeySizes` / `allowInvalidAsymmetricKeyTypes` (footguns)
- `zip: 'DEF'` compression
- `x5u` URL fetch (SSRF surface)
- SHA-1 based algorithms

## Tests

**96 tests** covering the algorithm matrix, PEM / X.509 / string /
Buffer / JWK / JWK-array / async-resolver key inputs, the full claim
surface (`exp`, `nbf`, `iat`, `maxAge`, `iss` / `aud` / `sub` / `nonce`
matchers, `requiredClaims`, `requiredScopes`, `typ`, `currentDate`),
tokenPair (create / rotate / reuse-detection / grace-window /
detectReuse-off / revoke / revokeAll), stores (memory GC strategies +
custom impl + redis dialect detection), and a CVE-labelled security
suite (CVE-2015-9235 algorithm confusion, CVE-2015-2951 `alg: 'none'`,
silent-allowlist regressions, tamper detection, shape guards, key
material minimums, DoS via `maxTokenSize`).
