# @exortek/jwk

> JSON Web Key for Node.js 22+ — **RFC 7517** / **RFC 7638** / **RFC 8037** / **RFC 9278**. Zero-dependency, built on `node:crypto`.

[![npm](https://img.shields.io/npm/v/@exortek/jwk.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/jwk)
[![tests](https://img.shields.io/badge/tests-34%20passing-brightgreen)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/@exortek/jwk.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/jwk)](https://packagephobia.com/result?p=@exortek/jwk)
[![types](https://img.shields.io/badge/types-included-3178C6)](./dist/index.d.ts)
[![license](https://img.shields.io/npm/l/@exortek/jwk.svg?color=blue)](./LICENSE)

Generate, import, export, thumbprint EC / RSA / OKP / oct keys. Modern helpers `jose` doesn't ship:
`toPublic` (defensive private-member strip), `matches` (thumbprint-based semantic equality),
`thumbprintURI` (RFC 9278), strict RFC 7517 §4.3 `use` / `key_ops` consistency, `requirePublic` /
`requirePrivate` validation guards.

📖 **Docs:** [**auth.memet.dev/jwk**](https://auth.memet.dev/jwk)

## Why

The JWK space is dominated by `jose` — a fine library, but its API leaves gaps that every consumer
ends up filling: nobody remembers which member holds the secret when stripping a private JWK for a
public JWKS endpoint; nobody wants to hand-roll thumbprint equality; nobody wants to discover their
`use: 'sig'` key silently accepted `key_ops: ['encrypt']` at 3 AM. `@exortek/jwk` closes those:

- **`toPublic(jwk)`** — one call strips `d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`. Type-agnostic; safe
  for JWKS endpoints. Throws on `oct` because symmetric keys have no public projection.
- **`matches(a, b)`** — thumbprint-based semantic equality across private ↔ public projections.
- **`thumbprintURI(jwk)`** — RFC 9278 URI form: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:…`
- **Strict validation** — partial RSA CRT parameters rejected, base64url length checked per curve,
  `use` / `key_ops` consistency enforced per RFC 7517 §4.3, `requirePublic` / `requirePrivate`
  guards.
- **Modern curves** — Ed25519 / Ed448 / X25519 / X448 (RFC 8037) and `secp256k1` (RFC 8812, Web3
  interop) alongside classic P-256 / P-384 / P-521.

## Install

```bash
npm  install @exortek/jwk
yarn add     @exortek/jwk
pnpm add     @exortek/jwk
```

Requires **Node.js 22 or newer**. Zero runtime dependencies.

## Quick start

```js
import { jwk } from '@exortek/jwk'

// 1. Generate — asymmetric returns both projections, `oct` returns one.
const { publicJwk, privateJwk } = await jwk.generate('EC', {
  curve: 'P-256',
  use: 'sig',
  alg: 'ES256',
  kid: 'signing-key-2026',
})

// 2. Thumbprint — stable identifier + RFC 9278 URI form.
const tp  = await jwk.thumbprint(publicJwk)
const uri = await jwk.thumbprintURI(publicJwk)

// 3. Publish safely — strips every private member.
const publishable = jwk.toPublic(privateJwk)

// 4. Match — semantic equality, insensitive to `kid` / `use` decoration.
await jwk.matches(publicJwk, privateJwk)  // → true

// 5. Interop — JWK ↔ node:crypto.KeyObject ↔ PEM.
const key = await jwk.import(privateJwk)
const pem = await jwk.export(key, { format: 'pem' })
```

## Modules

| Module              | Purpose                                                                                                                       |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `generate`          | EC (P-256/384/521, secp256k1), RSA (≥2048), OKP (Ed25519/Ed448/X25519/X448), oct — public/private projections in one call     |
| `import` / `export` | JWK ↔ `KeyObject` roundtrip, PEM (SPKI / PKCS#8 / X.509) import/export, defensive `toPublic()` for JWKS publishing            |
| `thumbprint`        | RFC 7638 canonical-form digest, RFC 9278 URI form, thumbprint-based `matches()` semantic equality                             |
| `validate`          | RFC 7517 §4 + RFC 7518 §6 + RFC 8037 §2 strict shape checking, `use`/`key_ops` consistency, `requirePublic`/`requirePrivate`  |

## Import styles

```js
// 1. Namespace — mirrors the ARCHITECTURE example.
import { jwk } from '@exortek/jwk'

// 2. Named — smallest bundle, tree-shakeable.
import { generate, importJWK, exportJWK, thumbprint, toPublic, matches } from '@exortek/jwk'

// 3. Subpath — one concern at a time.
import { generate }             from '@exortek/jwk/generate'
import { importJWK, importPEM } from '@exortek/jwk/import'
import { exportJWK, exportPEM } from '@exortek/jwk/export'
import { thumbprint, matches }  from '@exortek/jwk/thumbprint'
import { validate, isValid }    from '@exortek/jwk/validate'
```

## Error handling

Every recoverable failure throws `JwkError` with a stable `ErrorCode`. Branch on `code`, never on
the message.

```js
import { jwk, JwkError, ErrorCode } from '@exortek/jwk'

try {
  jwk.validate(untrustedJwk, { requirePublic: true })
} catch (err) {
  if (!(err instanceof JwkError)) throw err
  if (err.code === ErrorCode.INVALID_JWK)             { /* shape / length / secret leaked */ }
  if (err.code === ErrorCode.UNSUPPORTED_CURVE)       { /* unknown crv */ }
  if (err.code === ErrorCode.KEY_OPS_CONFLICT)        { /* use + key_ops inconsistent */ }
  if (err.code === ErrorCode.MISSING_REQUIRED_MEMBER) { /* missing kty / x / y / n / … */ }
}
```

Codes: `INVALID_ARGUMENT`, `UNSUPPORTED_KTY`, `UNSUPPORTED_CURVE`, `UNSUPPORTED_ALGORITHM`,
`INVALID_KEY`, `INVALID_JWK`, `INVALID_FORMAT`, `MISSING_REQUIRED_MEMBER`, `KEY_OPS_CONFLICT`.

## Post-quantum roadmap

Post-quantum signatures (**ML-DSA** — FIPS 204, formerly Dilithium) and
key-encapsulation (**ML-KEM** — FIPS 203, formerly Kyber) are on the
roadmap, but shipping them today would mean bundling a JS implementation
of NIST-selected lattice cryptography — a red line we're not crossing.
The correct path is `node:crypto` native support:

- **OpenSSL** added ML-DSA / ML-KEM in **3.5** (April 2025).
- **Node.js 22 – 24** ship OpenSSL 3.0 – 3.4; no `generateKeyPair('ml-dsa-65')` yet.
- **Node.js 25/26** (2026 – 2027) will expose these once the OpenSSL bump lands.
- **IETF** — `draft-ietf-jose-pqc` (JWK / JWS registrations, provisional `kty: "AKP"`) is still a draft.

When both boxes tick — Node native primitives *and* a stable JOSE
registration — we'll add `generate('ML-DSA-{44,65,87}')` and
`generate('ML-KEM-{512,768,1024}')` to this same surface, plus the
corresponding `crv` / `alg` support in `validate`, `import`, `export`,
and `thumbprint`. Until then the API stays where the standards are.

Need PQ today? [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) is a
credible, audited JS implementation you can plug into your own code path.

## Highlights

- **Strict base64url.** Rejects padding, whitespace, out-of-alphabet characters, and non-canonical
  encodings via a roundtrip check — Node's decoder is lenient by default, we tighten it at the
  JWK boundary.
- **Partial-RSA-CRT protection.** RFC 7518 §6.3.2 says private RSA JWKs must ship all of
  `p / q / dp / dq / qi` or none — we reject the middle ground that would otherwise silently
  degrade key import performance.
- **Ambiguous PEM rejection.** `exportPEM(privateKey, 'spki')` throws — you get a clear error
  telling you to extract the public key first with `createPublicKey(privateKey)` instead of a
  silent public projection.
- **`toPublic` on `oct` refuses.** Symmetric keys have no public form; the error catches accidental
  JWKS publication of a secret.
- **`matches` is timing-safe by construction.** Thumbprints are public — string equality is the
  correct primitive; no need to reach for `crypto.timingSafeEqual` on a hash you'd otherwise be
  shipping over the wire.
- **RFC 8812 `secp256k1`** shipped alongside P-256 / P-384 / P-521 for Web3 interop.

## Links

- **Source:** [github.com/ExorTek/auth](https://github.com/ExorTek/auth)
- **Issues & discussions:** [github.com/ExorTek/auth/issues](https://github.com/ExorTek/auth/issues)
- **Changelog:** [CHANGELOG.md](./CHANGELOG.md)

## License

MIT © ExorTek — see [LICENSE](./LICENSE).
