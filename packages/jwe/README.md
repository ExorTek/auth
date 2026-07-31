# @exortek/jwe

> JSON Web Encryption for Node.js 22+ — **RFC 7516** (JWE core), **RFC 7518 §4–§5** (JWA key management + content encryption), **RFC 8725** (BCP). Zero-dependency, built on `node:crypto`.

[![npm](https://img.shields.io/npm/v/@exortek/jwe.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/jwe)
[![tests](https://github.com/ExorTek/auth/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/@exortek/jwe.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/jwe)](https://packagephobia.com/result?p=@exortek/jwe)
[![types](https://img.shields.io/badge/types-included-3178C6)](./dist/index.d.ts)
[![license](https://img.shields.io/npm/l/@exortek/jwe.svg?color=blue)](./LICENSE)

Encrypt and decrypt JWE in compact + JSON serialisation. Where
[`@exortek/jws`](https://www.npmjs.com/package/@exortek/jws) signs a payload so
anyone with the public key can read it, `@exortek/jwe` *encrypts* it so only the
holder of the private key can. Covers RSA-OAEP, ECDH-ES (direct + key-wrap),
AES-KW, and direct (`dir`) key management over AES-GCM and AES-CBC-HMAC content
encryption. Server-only, zero runtime dependencies.

📖 **Docs:** [**auth.memet.dev/jwe**](https://auth.memet.dev/jwe)

## Why

`jose` is the reference JOSE library, but — as with JWS verification — its
decrypt contract lets you leave the algorithm allowlist off by mistake. This
package sits deliberately in the JWE layer, is server-only, and enforces:

- **Mandatory `alg` + `enc` allowlists on `decrypt`.** Omitting either raises
  `MISSING_ALG_ALLOWLIST` / `MISSING_ENC_ALLOWLIST`. No default, no fallback.
- **`RSA1_5` refused everywhere.** The padding-oracle-prone algorithm has no
  registry entry (`UNSUPPORTED_ALGORITHM`), the same posture `@exortek/jws`
  takes toward `alg: 'none'`. Tracks `draft-ietf-jose-deprecate-none-rsa15`.
- **Every integrity failure collapses to one code.** Bad tag, wrong key, or a
  tampered segment all raise `DECRYPTION_FAILED` — nothing leaks to an attacker.
- **Granular `ErrorCode` enum.** `switch (err.code)` beats string-matching.

## Algorithms

| `alg` (key management) | `enc` (content encryption) |
| --- | --- |
| `RSA-OAEP`, `RSA-OAEP-256` | `A128GCM`, `A192GCM`, `A256GCM` |
| `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A256KW` | `A128CBC-HS256`, `A256CBC-HS512` |
| `A128KW`, `A256KW`, `dir` | |

`RSA1_5` is intentionally unsupported. ECDH-ES accepts EC (P-256/P-384/P-521)
and X25519 keys.

## Install

```bash
npm install @exortek/jwe
```

Node.js **22 or newer**.

## Usage

```js
import { jwe } from '@exortek/jwe';

// Recipient has an EC or RSA key pair; you hold only their public key.
const token = await jwe.encrypt({ userId: 1, scope: 'admin' }, recipientPublicKey, {
  alg: 'ECDH-ES+A256KW',
  enc: 'A256GCM',
  expiresIn: '1h',
});

const { payload, protectedHeader } = await jwe.decrypt(token, recipientPrivateKey, {
  alg: ['ECDH-ES+A256KW'],
  enc: ['A256GCM'],
});
```

Payloads may be a JSON-serialisable value, a string, or raw bytes
(`Buffer` / `Uint8Array`) — binary round-trips untouched. Keys may be a
`KeyObject`, a JWK, a PEM string (asymmetric), or raw key material / an `oct`
JWK (symmetric).

### Direct and symmetric key management

```js
import { randomBytes } from 'node:crypto';

const key = randomBytes(32); // 256-bit CEK
const token = await jwe.encrypt({ hello: 'world' }, key, { alg: 'dir', enc: 'A256GCM' });
const { payload } = await jwe.decrypt(token, key, { alg: ['dir'], enc: ['A256GCM'] });
```

### JSON serialization (multi-recipient)

```js
const encrypted = await jwe.encryptJson(payload, [
  { key: rsaPublicKey, alg: 'RSA-OAEP-256', kid: 'r1' },
  { key: ecPublicKey, alg: 'ECDH-ES+A256KW', kid: 'e1' },
], { enc: 'A256GCM' });

// Either recipient's private key recovers the same payload.
const { payload: out } = await jwe.decryptJson(encrypted, rsaPrivateKey, {
  alg: ['RSA-OAEP-256', 'ECDH-ES+A256KW'],
  enc: ['A256GCM'],
});
```

### Inspect without decrypting

```js
import { decodeProtectedHeader } from '@exortek/jwe';

const { alg, enc, kid } = decodeProtectedHeader(token); // never gate auth on this
```

## Errors

Every failure throws a `JweError` with a stable `code` from `ErrorCode`:
`MISSING_ALG_ALLOWLIST`, `MISSING_ENC_ALLOWLIST`, `ALGORITHM_MISMATCH`,
`ENCRYPTION_MISMATCH`, `UNSUPPORTED_ALGORITHM`, `UNSUPPORTED_ENCRYPTION`,
`INVALID_KEY`, `INVALID_HEADER`, `INVALID_TOKEN`, `CRIT_UNSUPPORTED`,
`DECRYPTION_FAILED`, `TOKEN_TOO_LARGE`, and `TOKEN_EXPIRED`. Each carries an
HTTP `status` for middleware translation.

## License

[MIT](./LICENSE) © ExorTek.
