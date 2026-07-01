# @exortek/crypto

> Zero-dependency cryptographic primitives for the `@exortek/auth` stack. Built on `node:crypto`. Server-only.

This is the root of the dependency graph — every other `@exortek/*` package builds on top of these primitives. Four modules, each consumable on its own subpath.

## Install

```bash
yarn add @exortek/crypto
```

Requires Node.js 22 or newer.

## Hash

```js
import { hash, hmac, compare } from '@exortek/crypto/hash'

const h = await hash('hello world') // sha256 by default
const h2 = await hash('hello', { algo: 'sha512' })
const mac = await hmac('data', 'secret-key')
const ok = await compare('input-hash', storedHash) // timing-safe
```

Algorithms: `sha256` (default), `sha384`, `sha512`, `md5`.

## Cipher — 4 levels

```js
import { cipher } from '@exortek/crypto/cipher'

// 1. Symmetric (AES-256-GCM default)
const key = await cipher.generateKey()
const { ciphertext, iv, tag } = await cipher.encrypt('data', key)
const plain = await cipher.decrypt(ciphertext, key, { iv, tag })

// String shorthand — packs iv|tag|ciphertext as base64url
const token = await cipher.encryptToString('user:123', key)
const original = await cipher.decryptFromString(token, key)

// 2. Asymmetric (RSA-OAEP)
const { publicKey, privateKey } = await cipher.generateKeyPair('rsa-oaep')
const enc = await cipher.encrypt('msg', publicKey, { algo: 'rsa-oaep' })
const dec = await cipher.decrypt(enc, privateKey, { algo: 'rsa-oaep' })

// 3. Hybrid (RSA-wrapped AES key for large payloads)
const env = await cipher.encryptHybrid(largeData, publicKey)
const plain2 = await cipher.decryptHybrid(env, privateKey)

// 4. ECDH / X25519 — derive a shared secret
const alice = await cipher.generateKeyPair('ecdh-p256')
const bob = await cipher.generateKeyPair('ecdh-p256')
const shared = await cipher.deriveSharedSecret(alice.privateKey, bob.publicKey)
```

| Category      | Algorithms                                            |
| ------------- | ----------------------------------------------------- |
| Symmetric     | `aes-256-gcm` (default), `chacha20-poly1305`, `aes-256-cbc` |
| Asymmetric    | `rsa-oaep`, `rsa-oaep-256`                            |
| Key agreement | `ecdh-p256`, `ecdh-p384`, `x25519`                    |

## Encode

```js
import { base64url, hex } from '@exortek/crypto/encode'

base64url.encode('hello') // URL-safe, no padding
base64url.decode('aGVsbG8')
hex.encode(buffer)
hex.decode('deadbeef')
```

## Random

```js
import { random } from '@exortek/crypto/random'

random.bytes(32) // Buffer
random.hex(32) // hex string
random.base64url(32) // URL-safe base64
random.alphanumeric(21) // nanoid-style
random.numeric(6) // '847291' — OTP
random.uuid() // UUID v4
random.ulid() // 26-char sortable ID
random.token(32, 'usr') // 'usr_a3f9b2...' — prefixed
```

## License

MIT
