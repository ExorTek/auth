/**
 * Signing/verification key normaliser factory — turn a caller-supplied
 * key input (KeyObject, Buffer / Uint8Array, or JWK object) into a
 * concrete Node `KeyObject`, enforcing per-alg compatibility so
 * alg-confusion attacks surface as a clean `INVALID_KEY` at the key
 * boundary rather than a cryptic Node error deep in `crypto.sign`.
 *
 * jws consumes this directly; jwt wraps it with its own PEM / X.509
 * branch (which needs `_fromString` handling that jws does not accept).
 *
 * Callers inject their typed error class + code map + alg lookup:
 *
 *   const { normalizeKey } = createKeyNormalizer({
 *     ErrorClass: JwsError,
 *     ErrorCode,
 *     lookupAlg,
 *   });
 *
 * The returned helpers `assertKeyObject`, `assertPemKeyType`,
 * `assertRsaModulus`, and `nodeKeyType` are exposed so the wrapping
 * package can share them from its PEM branch too.
 */

import { KeyObject, createPrivateKey, createPublicKey, createSecretKey } from 'node:crypto';

/**
 * @typedef {object} AlgDescriptor
 * @property {'HMAC' | 'RSA' | 'RSA-PSS' | 'ECDSA' | 'EdDSA'} family
 * @property {string} [kty]
 * @property {string} [curve]
 * @property {number} [hmacMinBytes]
 */

/**
 * @param {object} opts
 * @param {new (code: string, message: string, options?: object) => Error} opts.ErrorClass
 * @param {{ INVALID_KEY: string }} opts.ErrorCode
 * @param {(alg: string) => AlgDescriptor} opts.lookupAlg
 */
export function createKeyNormalizer({ ErrorClass, ErrorCode, lookupAlg }) {
  /**
   * @param {AlgDescriptor} meta
   * @returns {string[] | null}
   */
  function nodeKeyType(meta) {
    switch (meta.family) {
      case 'RSA':
      case 'RSA-PSS':
        return ['rsa', 'rsa-pss'];
      case 'ECDSA':
        return ['ec'];
      case 'EdDSA':
        return ['ed25519', 'ed448'];
      default:
        return null;
    }
  }

  /**
   * RFC 7518 §3.3 (RS*) and §3.5 (PS*) both mandate a modulus of at
   * least 2048 bits. Enforce, matching the HMAC minimum-length policy
   * already applied to HS*.
   *
   * @param {KeyObject} key
   * @param {AlgDescriptor} meta
   * @param {string} alg
   */
  function assertRsaModulus(key, meta, alg) {
    if (meta.family !== 'RSA' && meta.family !== 'RSA-PSS') return;
    const details = key.asymmetricKeyDetails;
    const modulusLength = details && details.modulusLength;
    if (typeof modulusLength === 'number' && modulusLength < 2048) {
      throw new ErrorClass(
        ErrorCode.INVALID_KEY,
        `alg ${alg} requires an RSA key of at least 2048 bits (RFC 7518 §3.3 / §3.5); got ${modulusLength}`,
      );
    }
  }

  /**
   * Assert asymmetric key type matches the alg family (rsa / ec / ed*).
   *
   * @param {KeyObject} key
   * @param {AlgDescriptor} meta
   * @param {string} alg
   */
  function assertPemKeyType(key, meta, alg) {
    const nodeType = key.asymmetricKeyType;
    const expected = nodeKeyType(meta);
    if (nodeType && expected && !expected.includes(nodeType)) {
      throw new ErrorClass(
        ErrorCode.INVALID_KEY,
        `alg ${alg} expects key type ${expected.join(' | ')}; got ${nodeType}`,
      );
    }
  }

  /**
   * @param {KeyObject} key
   * @param {AlgDescriptor} meta
   * @param {'sign' | 'verify'} direction
   * @param {string} alg
   */
  function assertKeyObject(key, meta, direction, alg) {
    if (meta.family === 'HMAC') {
      if (key.type !== 'secret') {
        throw new ErrorClass(
          ErrorCode.INVALID_KEY,
          `alg ${alg} requires a secret KeyObject; got type=${key.type}`,
        );
      }
      if (
        meta.hmacMinBytes &&
        typeof key.symmetricKeySize === 'number' &&
        key.symmetricKeySize < meta.hmacMinBytes
      ) {
        throw new ErrorClass(
          ErrorCode.INVALID_KEY,
          `alg ${alg} requires a secret of at least ${meta.hmacMinBytes} bytes (RFC 7518 §3.2); got ${key.symmetricKeySize}`,
        );
      }
      return;
    }
    if (direction === 'sign' && key.type !== 'private') {
      throw new ErrorClass(
        ErrorCode.INVALID_KEY,
        `alg ${alg} requires a private KeyObject for signing; got type=${key.type}`,
      );
    }
    assertPemKeyType(key, meta, alg);
    assertRsaModulus(key, meta, alg);
  }

  /**
   * @param {Buffer | Uint8Array} key
   * @param {AlgDescriptor} meta
   * @param {string} alg
   */
  function fromBytes(key, meta, alg) {
    if (meta.family !== 'HMAC') {
      throw new ErrorClass(
        ErrorCode.INVALID_KEY,
        `alg ${alg} requires an asymmetric key; raw bytes are HMAC-only`,
      );
    }
    if (meta.hmacMinBytes && key.byteLength < meta.hmacMinBytes) {
      throw new ErrorClass(
        ErrorCode.INVALID_KEY,
        `alg ${alg} requires a secret of at least ${meta.hmacMinBytes} bytes (RFC 7518 §3.2); got ${key.byteLength}`,
      );
    }
    return createSecretKey(Buffer.isBuffer(key) ? key : Buffer.from(key));
  }

  /**
   * @param {Record<string, unknown>} jwk
   * @param {AlgDescriptor} meta
   * @param {'sign' | 'verify'} direction
   * @param {string} alg
   */
  function fromJwk(jwk, meta, direction, alg) {
    if (jwk.kty !== meta.kty) {
      throw new ErrorClass(
        ErrorCode.INVALID_KEY,
        `alg ${alg} expects JWK kty=${meta.kty}; got ${JSON.stringify(jwk.kty)}`,
      );
    }
    if (meta.kty === 'EC' && meta.curve && jwk.crv !== meta.curve) {
      throw new ErrorClass(
        ErrorCode.INVALID_KEY,
        `alg ${alg} expects JWK crv=${meta.curve}; got ${JSON.stringify(jwk.crv)}`,
      );
    }
    if (meta.kty === 'oct') {
      if (typeof jwk.k !== 'string') {
        throw new ErrorClass(ErrorCode.INVALID_KEY, `alg ${alg}: JWK oct requires string "k"`);
      }
      const bytes = Buffer.from(jwk.k, 'base64url');
      if (meta.hmacMinBytes && bytes.byteLength < meta.hmacMinBytes) {
        throw new ErrorClass(
          ErrorCode.INVALID_KEY,
          `alg ${alg} requires a secret of at least ${meta.hmacMinBytes} bytes (RFC 7518 §3.2); got ${bytes.byteLength}`,
        );
      }
      return createSecretKey(bytes);
    }
    const hasPrivate = 'd' in jwk;
    if (direction === 'sign' && !hasPrivate) {
      throw new ErrorClass(
        ErrorCode.INVALID_KEY,
        `alg ${alg}: sign requires a private JWK (with "d"); got a public-only JWK`,
      );
    }
    try {
      const keyObj = hasPrivate
        ? createPrivateKey({ key: /** @type {any} */ (jwk), format: 'jwk' })
        : createPublicKey({ key: /** @type {any} */ (jwk), format: 'jwk' });
      assertRsaModulus(keyObj, meta, alg);
      return keyObj;
    } catch (err) {
      if (err instanceof ErrorClass) throw err;
      throw new ErrorClass(
        ErrorCode.INVALID_KEY,
        `alg ${alg}: node:crypto rejected the JWK — ${err instanceof Error ? err.message : String(err)}`,
        { cause: err },
      );
    }
  }

  /**
   * The common core: KeyObject / raw bytes / JWK object → KeyObject.
   * Returns `null` if the input is none of these (caller may recognise
   * a package-specific shape like a PEM string).
   *
   * @param {unknown} key
   * @param {string} alg
   * @param {'sign' | 'verify'} direction
   * @returns {Promise<KeyObject | null>}
   */
  async function normalizeCore(key, alg, direction) {
    const meta = lookupAlg(alg);
    if (key instanceof KeyObject) {
      assertKeyObject(key, meta, direction, alg);
      return key;
    }
    if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
      return fromBytes(/** @type {Buffer | Uint8Array} */ (key), meta, alg);
    }
    if (key && typeof key === 'object' && 'kty' in /** @type {any} */ (key)) {
      return fromJwk(/** @type {Record<string, unknown>} */ (key), meta, direction, alg);
    }
    return null;
  }

  /**
   * Whole-surface normaliser for packages that only accept the three
   * shared shapes — used directly by jws. jwt wraps `normalizeCore`
   * instead and adds its own PEM branch.
   *
   * @param {unknown} key
   * @param {string} alg
   * @param {'sign' | 'verify'} direction
   * @returns {Promise<KeyObject>}
   */
  async function normalizeKey(key, alg, direction) {
    const out = await normalizeCore(key, alg, direction);
    if (out !== null) return out;
    throw new ErrorClass(
      ErrorCode.INVALID_KEY,
      `unsupported key input for alg ${alg}: expected KeyObject | Buffer | JWK, got ${typeof key}`,
    );
  }

  return {
    normalizeKey,
    normalizeCore,
    assertKeyObject,
    assertPemKeyType,
    assertRsaModulus,
    nodeKeyType,
  };
}
