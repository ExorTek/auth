# @exortek/jwt

> JSON Web Token for Node.js 22+ — **RFC 7519** + **RFC 8725** (BCP) + **RFC 9068** (OAuth2 profile). Zero-dependency, built on `node:crypto`.

> _Scaffold — v0.0.0. The public API is being filled in phase by phase. Wait for 1.0.0 for shipping-quality docs._

The twelve differentiators that will land with 1.0.0:

- **`tokenPair`** — access + refresh with **reuse detection** (RFC 6749 §10.4). No other JWT library ships this.
- **Mandatory `alg` allowlist on verify.** Omission raises `MISSING_ALG_ALLOWLIST`.
- **`alg: 'none'` refused everywhere.** No flag, no environment variable — hardcoded rejection with `ALGORITHM_NONE_FORBIDDEN`.
- **Blacklist store** (memory / redis / custom) with GC strategies.
- **Custom function escape hatch on every knob** — `hashFn`, `generate`, `issuer`, `audience` predicates, encoding.
- **`typ` enforcement + RFC 9068 (`at+jwt`) preset.**
- **`maxAge` — iat freshness policy** for leaked-token mitigation.
- **`scope` validation first-class** — `requiredScopes: ['read:users']`.
- **`peek`** — signature-verified inspection without claim checks.
- **`sign` metadata return** — `{ token, jti, expiresAt, issuedAt, alg, kid }`.
- **`aud` array + `iss` array on verify** — multi-tenant support out of the box.
- **PEM string + X.509 certificate input** — pass the raw file contents; we auto-detect the header.

## License

MIT © ExorTek — see [LICENSE](./LICENSE).
