# @exortek/jws

> JSON Web Signature for Node.js 22+ — **RFC 7515** (JWS core), **RFC 7518** (JWA), **RFC 7797** (unencoded payload), **RFC 8037** (Ed25519 / Ed448), **RFC 8812** (`secp256k1`). Zero-dependency, built on `node:crypto`.

> _Scaffold — v0.0.0. The public API is being filled in phase by phase. See the [plan](../../.claude/plans) or wait for 1.0.0 for shipping-quality docs._

The five differentiators that will land with 1.0.0:

- **Mandatory `alg` allowlist on `verify`.** Omitting it raises `MISSING_ALG_ALLOWLIST`.
- **`alg: 'none'` refused everywhere.** Not a flag, not a config, not an environment variable — hardcoded rejection with a dedicated `ALGORITHM_NONE_FORBIDDEN` code.
- **`crit` strict by default.** Unknown critical headers raise `CRIT_UNSUPPORTED`.
- **Async key resolver as a first-class input** — `verify(token, async header => key, { alg: [...] })`.
- **Granular `ErrorCode` enum.** 13 machine-branchable codes, not generic error classes.

## License

MIT © ExorTek — see [LICENSE](./LICENSE).
