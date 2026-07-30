# @exortek/jwe

> JSON Web Encryption for Node.js 22+ — **RFC 7516** (JWE core), **RFC 7518 §4–§5** (JWA key management + content encryption), **RFC 8725** (BCP). Zero-dependency, built on `node:crypto`.

[![npm](https://img.shields.io/npm/v/@exortek/jwe.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/jwe)
[![tests](https://github.com/ExorTek/auth/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/@exortek/jwe.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/jwe)](https://packagephobia.com/result?p=@exortek/jwe)
[![types](https://img.shields.io/badge/types-included-3178C6)](./dist/index.d.ts)
[![license](https://img.shields.io/npm/l/@exortek/jwe.svg?color=blue)](./LICENSE)

Encrypt and decrypt JWE in compact + JSON serialisation. Covers RSA-OAEP,
ECDH-ES (direct + key-wrap), AES-KW, and direct (`dir`) key management over
AES-GCM and AES-CBC-HMAC content encryption. Server-only, zero runtime
dependencies.

📖 **Docs:** [**auth.memet.dev/jwe**](https://auth.memet.dev/jwe)

> **Status:** early scaffold. The package surface, algorithm registries, and
> unsafe `decode` are in place; the encrypt / decrypt core is under active
> development and not yet published.

## Why

`jose` is the reference JOSE library, but — as with JWS verification — its
decrypt contract lets you leave the algorithm allowlist off by mistake. This
package sits deliberately in the JWE layer, is server-only, has zero runtime
dependencies, and enforces:

- **Mandatory `alg` + `enc` allowlists on `decrypt`.** No default, no fallback.
- **`RSA1_5` refused everywhere.** No flag, no configuration — the padding-oracle
  algorithm has no registry entry (`UNSUPPORTED_ALGORITHM`), the same posture
  `@exortek/jws` takes toward `alg: 'none'`. Tracks
  `draft-ietf-jose-deprecate-none-rsa15`.
- **Granular `ErrorCode` enum.** Machine-branchable codes; `switch (err.code)`
  beats string-matching on `err.message`.

## Algorithms

| `alg` (key management) | `enc` (content encryption) |
| --- | --- |
| `RSA-OAEP`, `RSA-OAEP-256` | `A128GCM`, `A192GCM`, `A256GCM` |
| `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A256KW` | `A128CBC-HS256`, `A256CBC-HS512` |
| `A128KW`, `A256KW`, `dir` | |

`RSA1_5` is intentionally unsupported.

## Install

```bash
npm install @exortek/jwe
```

Node.js **22 or newer**.

## Usage

```js
import { jwe } from '@exortek/jwe';

const token = await jwe.encrypt({ userId: 1, scope: 'admin' }, publicKey, {
  alg: 'ECDH-ES+A256KW',
  enc: 'A256GCM',
  expiresIn: '1h',
});

const { payload } = await jwe.decrypt(token, privateKey, {
  alg: ['ECDH-ES+A256KW'],
  enc: ['A256GCM'],
});
```

## License

[MIT](./LICENSE) © ExorTek.
