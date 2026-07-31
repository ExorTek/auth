/**
 * Key material handling for PASETO v4.
 *
 *   - v4.local  keys are raw 32-byte symmetric secrets.
 *   - v4.public keys are Ed25519. PASETO serialises them raw — a 32-byte
 *     public key, and a 64-byte secret key (`seed ‖ public`). Node wants
 *     a `KeyObject`, so we bridge raw bytes ⇄ `KeyObject` through JWK.
 */

import { createPrivateKey, createPublicKey, KeyObject } from 'node:crypto';

import { PasetoError, ErrorCode } from './errors.js';

const b64url = bytes => Buffer.from(bytes).toString('base64url');

// PKCS#8 prefix for an Ed25519 private key wrapping a bare 32-byte seed.
// Importing via PKCS#8 lets Node derive the public key from the seed, so
// a 32-byte-seed secret key works even without the public half.
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/**
 * Coerce a 32-byte symmetric key. Accepts Buffer/Uint8Array; strings are
 * rejected here — the public API decides how a string key is interpreted.
 * @param {Uint8Array} key
 * @returns {Buffer}
 */
export function symmetricKey(key) {
  if (!Buffer.isBuffer(key) && !(key instanceof Uint8Array)) {
    throw new PasetoError(ErrorCode.INVALID_KEY, 'v4.local key must be a 32-byte Buffer or Uint8Array');
  }
  if (key.length !== 32) {
    throw new PasetoError(ErrorCode.INVALID_KEY, `v4.local key must be exactly 32 bytes, got ${key.length}`);
  }
  return Buffer.from(key);
}

/**
 * Build an Ed25519 private `KeyObject` from a raw secret key.
 * Accepts an existing `KeyObject`, a 64-byte `seed ‖ public`, or a
 * 32-byte seed.
 * @param {KeyObject | Uint8Array} key
 * @returns {KeyObject}
 */
export function ed25519PrivateKey(key) {
  if (key instanceof KeyObject) {
    return key;
  }
  if (!Buffer.isBuffer(key) && !(key instanceof Uint8Array)) {
    throw new PasetoError(ErrorCode.INVALID_KEY, 'v4.public secret key must be a KeyObject, Buffer, or Uint8Array');
  }
  let seed;
  if (key.length === 64) {
    // seed ‖ public — the seed alone determines the key pair.
    seed = key.subarray(0, 32);
  } else if (key.length === 32) {
    seed = key;
  } else {
    throw new PasetoError(ErrorCode.INVALID_KEY, `v4.public secret key must be 32 or 64 bytes, got ${key.length}`);
  }
  try {
    const der = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
    return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  } catch (err) {
    throw new PasetoError(ErrorCode.INVALID_KEY, `v4.public secret key is not a valid Ed25519 key: ${err.message}`, {
      cause: err,
    });
  }
}

/**
 * Build an Ed25519 public `KeyObject` from a raw 32-byte public key
 * (or pass through an existing `KeyObject`).
 * @param {KeyObject | Uint8Array} key
 * @returns {KeyObject}
 */
export function ed25519PublicKey(key) {
  if (key instanceof KeyObject) {
    return key;
  }
  if (!Buffer.isBuffer(key) && !(key instanceof Uint8Array)) {
    throw new PasetoError(ErrorCode.INVALID_KEY, 'v4.public public key must be a KeyObject, Buffer, or Uint8Array');
  }
  if (key.length !== 32) {
    throw new PasetoError(ErrorCode.INVALID_KEY, `v4.public public key must be exactly 32 bytes, got ${key.length}`);
  }
  try {
    return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: b64url(key) }, format: 'jwk' });
  } catch (err) {
    throw new PasetoError(ErrorCode.INVALID_KEY, `v4.public public key is not a valid Ed25519 key: ${err.message}`, {
      cause: err,
    });
  }
}

/** Export an Ed25519 `KeyObject` back to its raw 32-byte form. */
export function rawFromKeyObject(keyObject) {
  const jwk = keyObject.export({ format: 'jwk' });
  const field = keyObject.type === 'private' ? jwk.d : jwk.x;
  return Buffer.from(field, 'base64url');
}
