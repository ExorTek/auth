/**
 * `@exortek/crypto` — zero-dependency cryptographic primitives built on `node:crypto`.
 *
 * Top-level entry that re-exports every module of the package. Consumers can
 * either pull the whole surface at once:
 *
 * ```js
 * import { hash, cipher, random, encode, CryptoError } from '@exortek/crypto'
 * ```
 *
 * or import only what they need through subpath entries for tighter bundles:
 *
 * ```js
 * import { hash }     from '@exortek/crypto/hash'
 * import { cipher }   from '@exortek/crypto/cipher'
 * import { random }   from '@exortek/crypto/random'
 * import { base64url } from '@exortek/crypto/encode'
 * ```
 *
 * Modules:
 *   - {@link ./random/index.js random}: bytes, hex, base64url, base64, crockford,
 *     base58, alphanumeric, numeric, pin, code, serial, token, uuid4/5/7, ulid.
 *   - {@link ./hash/index.js hash}: hash, hmac, compare (timing-safe).
 *   - {@link ./cipher/index.js cipher}: symmetric (AES-GCM/CBC, ChaCha20),
 *     asymmetric (RSA-OAEP), hybrid, ECDH/X25519 key agreement.
 *   - {@link ./encode/index.js encode}: base64url, base64, hex — encode/decode.
 *   - {@link ./errors.js errors}: `CryptoError` + stable `ErrorCode` enum.
 */

export * from './random/index.js';
export * from './hash/index.js';
export * from './cipher/index.js';
export * from './sign/index.js';
export * from './errors.js';
export * as encode from './encode/index.js';
