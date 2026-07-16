/**
 * Key material normaliser — turn JWK objects, `KeyObject`s, and
 * `Buffer` / `Uint8Array` HMAC secrets into the concrete `KeyObject`
 * shape the algorithms table expects.
 *
 * Enforces per-alg kty compatibility here so alg-confusion attacks
 * surface as a clean {@link ErrorCode.INVALID_KEY} at the key boundary
 * rather than a cryptic Node error deep in `crypto.sign`.
 */

import { KeyObject, createPrivateKey, createPublicKey, createSecretKey } from 'node:crypto';

import { JwsError, ErrorCode } from './errors.js';
import { lookup as lookupAlg } from './algorithms.js';

/**
 * @typedef {KeyObject | Buffer | Uint8Array | Record<string, unknown>} KeyInput
 */

/**
 * Normalise a caller-supplied key into a `KeyObject`.
 *
 * @param {KeyInput} key
 * @param {string} alg
 * @param {'sign' | 'verify'} direction
 * @returns {Promise<KeyObject>}
 */
export async function normalizeKey(key, alg, direction) {
  const meta = lookupAlg(alg);

  if (key instanceof KeyObject) {
    _assertKeyObject(key, meta, direction, alg);
    return key;
  }

  if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
    if (meta.family !== 'HMAC') {
      throw new JwsError(ErrorCode.INVALID_KEY, `alg ${alg} requires an asymmetric key; raw bytes are HMAC-only`);
    }
    if (meta.hmacMinBytes && key.byteLength < meta.hmacMinBytes) {
      throw new JwsError(
        ErrorCode.INVALID_KEY,
        `alg ${alg} requires a secret of at least ${meta.hmacMinBytes} bytes (RFC 7518 §3.2); got ${key.byteLength}`,
      );
    }
    return createSecretKey(Buffer.isBuffer(key) ? key : Buffer.from(key));
  }

  if (key && typeof key === 'object' && 'kty' in key) {
    return _fromJwk(/** @type {Record<string, unknown>} */ (key), meta, direction, alg);
  }

  throw new JwsError(
    ErrorCode.INVALID_KEY,
    `unsupported key input for alg ${alg}: expected KeyObject | Buffer | JWK, got ${typeof key}`,
  );
}

/**
 * @param {KeyObject} key
 * @param {import('./algorithms.js').AlgDescriptor} meta
 * @param {'sign' | 'verify'} direction
 * @param {string} alg
 */
function _assertKeyObject(key, meta, direction, alg) {
  if (meta.family === 'HMAC') {
    if (key.type !== 'secret') {
      throw new JwsError(ErrorCode.INVALID_KEY, `alg ${alg} requires a secret KeyObject; got type=${key.type}`);
    }
    return;
  }
  if (direction === 'sign' && key.type !== 'private') {
    throw new JwsError(
      ErrorCode.INVALID_KEY,
      `alg ${alg} requires a private KeyObject for signing; got type=${key.type}`,
    );
  }
  const nodeType = key.asymmetricKeyType;
  const expectedNodeType = _nodeKeyType(meta);
  if (nodeType && expectedNodeType && !expectedNodeType.includes(nodeType)) {
    throw new JwsError(
      ErrorCode.INVALID_KEY,
      `alg ${alg} expects key type ${expectedNodeType.join(' | ')}; got ${nodeType}`,
    );
  }
}

/**
 * @param {Record<string, unknown>} jwk
 * @param {import('./algorithms.js').AlgDescriptor} meta
 * @param {'sign' | 'verify'} direction
 * @param {string} alg
 */
async function _fromJwk(jwk, meta, direction, alg) {
  if (jwk.kty !== meta.kty) {
    throw new JwsError(ErrorCode.INVALID_KEY, `alg ${alg} expects JWK kty=${meta.kty}; got ${JSON.stringify(jwk.kty)}`);
  }

  if (meta.kty === 'EC' && meta.curve && jwk.crv !== meta.curve) {
    throw new JwsError(
      ErrorCode.INVALID_KEY,
      `alg ${alg} expects JWK crv=${meta.curve}; got ${JSON.stringify(jwk.crv)}`,
    );
  }

  if (meta.kty === 'oct') {
    if (typeof jwk.k !== 'string') {
      throw new JwsError(ErrorCode.INVALID_KEY, `alg ${alg}: JWK oct requires string "k"`);
    }
    const bytes = Buffer.from(jwk.k, 'base64url');
    if (meta.hmacMinBytes && bytes.byteLength < meta.hmacMinBytes) {
      throw new JwsError(
        ErrorCode.INVALID_KEY,
        `alg ${alg} requires a secret of at least ${meta.hmacMinBytes} bytes (RFC 7518 §3.2); got ${bytes.byteLength}`,
      );
    }
    return createSecretKey(bytes);
  }

  const hasPrivate = 'd' in jwk;
  if (direction === 'sign' && !hasPrivate) {
    throw new JwsError(
      ErrorCode.INVALID_KEY,
      `alg ${alg}: sign requires a private JWK (with "d"); got a public-only JWK`,
    );
  }

  try {
    return hasPrivate
      ? createPrivateKey({ key: /** @type {any} */ (jwk), format: 'jwk' })
      : createPublicKey({ key: /** @type {any} */ (jwk), format: 'jwk' });
  } catch (err) {
    throw new JwsError(
      ErrorCode.INVALID_KEY,
      `alg ${alg}: node:crypto rejected the JWK — ${err instanceof Error ? err.message : String(err)}`,
      { cause: err },
    );
  }
}

/**
 * @param {import('./algorithms.js').AlgDescriptor} meta
 * @returns {string[] | null}
 */
function _nodeKeyType(meta) {
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
