/**
 * Typed PASETO keys ("algorithm lucidity", PASETO spec §Key Considerations).
 *
 * A raw 32-byte buffer is indistinguishable between a `v4.local` secret and
 * a `v4.public` public key — so an app that mixes them up would let anyone
 * holding the public key mint `v4.local` tokens. Every key therefore
 * carries its version and purpose, and the API refuses a key of the wrong
 * purpose (or a bare buffer) with `INVALID_KEY_PURPOSE`:
 *
 *   const key = generateKey();                          // v4 local
 *   const { secretKey, publicKey } = generateKeyPair(); // v4 secret / public
 *   const imported = keys.local(rawBytesFromVault);     // wrap existing material
 *
 * `PasetoKey` instances are only created by this module; a look-alike plain
 * object is rejected.
 */

import { createPublicKey, KeyObject } from 'node:crypto';

import { ed25519PrivateKey, ed25519PublicKey, rawFromKeyObject, symmetricKey } from './internal/keys.js';
import { PasetoError, ErrorCode } from './internal/errors.js';

const CONSTRUCT = Symbol('PasetoKey');

/** @typedef {'local' | 'secret' | 'public'} KeyPurpose */

export class PasetoKey {
  /** @type {Buffer} raw wire form */
  #bytes;
  /** @type {Buffer | KeyObject | undefined} what the primitives consume, built once */
  #usable;

  /**
   * @param {symbol} token
   * @param {KeyPurpose} purpose
   * @param {Buffer} bytes
   */
  constructor(token, purpose, bytes) {
    if (token !== CONSTRUCT) {
      throw new PasetoError(
        ErrorCode.INVALID_ARGUMENT,
        'PasetoKey is created by generateKey / generateKeyPair / keys.local|secret|public',
      );
    }
    /** @type {'v4'} */
    this.version = 'v4';
    /** @type {KeyPurpose} */
    this.purpose = purpose;
    this.#bytes = bytes;
    Object.freeze(this);
  }

  /**
   * The key in PASETO's raw wire form: 32 bytes for `local` and `public`,
   * 64 bytes (`seed ‖ public`) for `secret`.
   *
   * @returns {Buffer}
   */
  export() {
    return Buffer.from(this.#bytes);
  }

  /** Never serialize key bytes by accident (logs, JSON responses). */
  toJSON() {
    return { version: this.version, purpose: this.purpose };
  }

  /**
   * @internal The material the v4 primitives take, built on first use.
   * @param {PasetoKey} key
   * @returns {Buffer | KeyObject}
   */
  static usable(key) {
    if (key.#usable === undefined) {
      key.#usable =
        key.purpose === 'local'
          ? symmetricKey(key.#bytes)
          : key.purpose === 'secret'
            ? ed25519PrivateKey(key.#bytes)
            : ed25519PublicKey(key.#bytes);
    }
    return key.#usable;
  }
}

/**
 * @param {KeyPurpose} purpose
 * @param {Buffer} bytes
 * @returns {PasetoKey}
 */
export function makeKey(purpose, bytes) {
  return new PasetoKey(CONSTRUCT, purpose, bytes);
}

/**
 * Resolve a key handed to a public API to the material its primitive takes,
 * refusing anything but a `PasetoKey` of the expected purpose.
 *
 * @param {unknown} key
 * @param {KeyPurpose} purpose
 * @param {string} where   e.g. `'encrypt'`
 * @returns {Buffer | KeyObject}
 */
export function resolveKey(key, purpose, where) {
  if (!(key instanceof PasetoKey)) {
    throw new PasetoError(
      ErrorCode.INVALID_KEY_PURPOSE,
      `${where} requires a v4 ${purpose} PasetoKey — wrap raw material with keys.${purpose}(…)`,
    );
  }
  if (key.purpose !== purpose) {
    throw new PasetoError(
      ErrorCode.INVALID_KEY_PURPOSE,
      `${where} requires a v4 ${purpose} key, got a ${key.purpose} key`,
    );
  }
  return PasetoKey.usable(key);
}

/**
 * Wrap existing key material in a typed key. The bytes are validated now,
 * not at first use.
 */
export const keys = Object.freeze({
  /**
   * A `v4.local` symmetric key from 32 raw bytes.
   * @param {Uint8Array} bytes
   * @returns {PasetoKey}
   */
  local(bytes) {
    return makeKey('local', symmetricKey(bytes));
  },

  /**
   * A `v4.public` secret (signing) key from a 64-byte `seed ‖ public`, a
   * 32-byte seed, or an Ed25519 private `KeyObject`.
   * @param {Uint8Array | KeyObject} material
   * @returns {PasetoKey}
   */
  secret(material) {
    if (material instanceof KeyObject && material.type !== 'private') {
      throw new PasetoError(ErrorCode.INVALID_KEY_PURPOSE, 'keys.secret requires a private Ed25519 key');
    }
    const privateKey = ed25519PrivateKey(material);
    const seed = rawFromKeyObject(privateKey);
    const pub = rawFromKeyObject(createPublicKey(privateKey));
    return makeKey('secret', Buffer.concat([seed, pub]));
  },

  /**
   * A `v4.public` public (verification) key from 32 raw bytes or an
   * Ed25519 public `KeyObject`.
   * @param {Uint8Array | KeyObject} material
   * @returns {PasetoKey}
   */
  public(material) {
    if (material instanceof KeyObject && material.type !== 'public') {
      throw new PasetoError(ErrorCode.INVALID_KEY_PURPOSE, 'keys.public requires a public Ed25519 key');
    }
    return makeKey('public', rawFromKeyObject(ed25519PublicKey(material)));
  },
});
