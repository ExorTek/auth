/**
 * Key material normaliser — turn a wide input surface into a concrete
 * `KeyObject` the algorithms table can consume.
 *
 * Beyond the shapes `@exortek/jws` accepts (`KeyObject`, `Buffer`,
 * JWK object), jwt also handles raw **PEM strings** and **X.509
 * certificates** — the shape most real-world code loads with
 * `fs.readFileSync('./private.pem', 'utf8')`. The header is inspected
 * to decide whether the string is a key, a cert, or an HMAC secret.
 *
 * Enforces per-alg kty compatibility and RSA modulus / HMAC minimum
 * lengths (RFC 7518 §3.2, §3.3, §3.5) — alg-confusion attacks surface
 * as a clean {@link ErrorCode.INVALID_KEY} at the key boundary rather
 * than a cryptic Node error deep in `crypto.sign`.
 */

import { KeyObject, createPrivateKey, createPublicKey, createSecretKey, X509Certificate } from 'node:crypto';

import { JwtError, ErrorCode } from './errors.js';
import { lookup as lookupAlg } from './algorithms.js';

/**
 * @typedef {KeyObject | Buffer | Uint8Array | string | Record<string, unknown>} KeyInput
 */

/**
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

  if (typeof key === 'string') {
    return _fromString(key, meta, direction, alg);
  }

  if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
    return _fromBytes(/** @type {Buffer | Uint8Array} */ (key), meta, direction, alg);
  }

  if (key && typeof key === 'object' && 'kty' in key) {
    return _fromJwk(/** @type {Record<string, unknown>} */ (key), meta, direction, alg);
  }

  throw new JwtError(
    ErrorCode.INVALID_KEY,
    `unsupported key input for alg ${alg}: expected KeyObject | Buffer | JWK | PEM string, got ${typeof key}`,
  );
}

/**
 * String input branch — the jwt-specific extension over jws. If the
 * input carries a PEM `-----BEGIN` marker we dispatch on the header;
 * otherwise the string is treated as a UTF-8 HMAC secret (the same
 * behaviour `jsonwebtoken` ships).
 *
 * @param {string} key
 * @param {import('./algorithms.js').AlgDescriptor} meta
 * @param {'sign' | 'verify'} direction
 * @param {string} alg
 */
function _fromString(key, meta, direction, alg) {
  if (key.includes('-----BEGIN ')) {
    try {
      if (key.includes('CERTIFICATE-----')) {
        if (direction === 'sign') {
          throw new JwtError(
            ErrorCode.INVALID_KEY,
            `alg ${alg}: X.509 certificates only carry a public key; signing requires the private counterpart`,
          );
        }
        const cert = new X509Certificate(key);
        _assertRsaModulus(cert.publicKey, meta, alg);
        _assertPemKeyType(cert.publicKey, meta, alg);
        return cert.publicKey;
      }
      if (key.includes('PRIVATE KEY-----')) {
        const k = createPrivateKey({ key, format: 'pem' });
        _assertKeyObject(k, meta, direction, alg);
        return k;
      }
      if (key.includes('PUBLIC KEY-----')) {
        if (direction === 'sign') {
          throw new JwtError(
            ErrorCode.INVALID_KEY,
            `alg ${alg}: public-key PEM cannot sign; supply the private-key counterpart`,
          );
        }
        const k = createPublicKey({ key, format: 'pem' });
        _assertPemKeyType(k, meta, alg);
        _assertRsaModulus(k, meta, alg);
        return k;
      }
      throw new JwtError(
        ErrorCode.INVALID_KEY,
        `unrecognised PEM header — expected PRIVATE KEY / PUBLIC KEY / CERTIFICATE / RSA PRIVATE KEY / EC PRIVATE KEY`,
      );
    } catch (err) {
      if (err instanceof JwtError) {
        throw err;
      }
      throw new JwtError(
        ErrorCode.INVALID_KEY,
        `alg ${alg}: node:crypto rejected the PEM — ${err instanceof Error ? err.message : String(err)}`,
        { cause: err },
      );
    }
  }

  // No PEM header → HMAC secret (UTF-8), matching jsonwebtoken.
  if (meta.family !== 'HMAC') {
    throw new JwtError(
      ErrorCode.INVALID_KEY,
      `alg ${alg}: string secret without a PEM header is only valid for HMAC algorithms`,
    );
  }
  const bytes = Buffer.from(key, 'utf8');
  if (meta.hmacMinBytes && bytes.byteLength < meta.hmacMinBytes) {
    throw new JwtError(
      ErrorCode.INVALID_KEY,
      `alg ${alg} requires a secret of at least ${meta.hmacMinBytes} bytes (RFC 7518 §3.2); got ${bytes.byteLength}`,
    );
  }
  return createSecretKey(bytes);
}

/**
 * @param {Buffer | Uint8Array} key
 * @param {import('./algorithms.js').AlgDescriptor} meta
 * @param {'sign' | 'verify'} _direction
 * @param {string} alg
 */
function _fromBytes(key, meta, _direction, alg) {
  if (meta.family !== 'HMAC') {
    throw new JwtError(ErrorCode.INVALID_KEY, `alg ${alg} requires an asymmetric key; raw bytes are HMAC-only`);
  }
  if (meta.hmacMinBytes && key.byteLength < meta.hmacMinBytes) {
    throw new JwtError(
      ErrorCode.INVALID_KEY,
      `alg ${alg} requires a secret of at least ${meta.hmacMinBytes} bytes (RFC 7518 §3.2); got ${key.byteLength}`,
    );
  }
  return createSecretKey(Buffer.isBuffer(key) ? key : Buffer.from(key));
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
      throw new JwtError(ErrorCode.INVALID_KEY, `alg ${alg} requires a secret KeyObject; got type=${key.type}`);
    }
    return;
  }
  if (direction === 'sign' && key.type !== 'private') {
    throw new JwtError(
      ErrorCode.INVALID_KEY,
      `alg ${alg} requires a private KeyObject for signing; got type=${key.type}`,
    );
  }
  _assertPemKeyType(key, meta, alg);
  _assertRsaModulus(key, meta, alg);
}

/**
 * Assert that the asymmetric key type on a KeyObject matches the alg's
 * expected family (rsa / ec / ed25519 / ed448).
 *
 * @param {KeyObject} key
 * @param {import('./algorithms.js').AlgDescriptor} meta
 * @param {string} alg
 */
function _assertPemKeyType(key, meta, alg) {
  const nodeType = key.asymmetricKeyType;
  const expected = _nodeKeyType(meta);
  if (nodeType && expected && !expected.includes(nodeType)) {
    throw new JwtError(ErrorCode.INVALID_KEY, `alg ${alg} expects key type ${expected.join(' | ')}; got ${nodeType}`);
  }
}

/**
 * @param {KeyObject} key
 * @param {import('./algorithms.js').AlgDescriptor} meta
 * @param {string} alg
 */
function _assertRsaModulus(key, meta, alg) {
  if (meta.family !== 'RSA' && meta.family !== 'RSA-PSS') {
    return;
  }
  const details = key.asymmetricKeyDetails;
  const modulusLength = details && details.modulusLength;
  if (typeof modulusLength === 'number' && modulusLength < 2048) {
    throw new JwtError(
      ErrorCode.INVALID_KEY,
      `alg ${alg} requires an RSA key of at least 2048 bits (RFC 7518 §3.3 / §3.5); got ${modulusLength}`,
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
    throw new JwtError(ErrorCode.INVALID_KEY, `alg ${alg} expects JWK kty=${meta.kty}; got ${JSON.stringify(jwk.kty)}`);
  }

  if (meta.kty === 'EC' && meta.curve && jwk.crv !== meta.curve) {
    throw new JwtError(
      ErrorCode.INVALID_KEY,
      `alg ${alg} expects JWK crv=${meta.curve}; got ${JSON.stringify(jwk.crv)}`,
    );
  }

  if (meta.kty === 'oct') {
    if (typeof jwk.k !== 'string') {
      throw new JwtError(ErrorCode.INVALID_KEY, `alg ${alg}: JWK oct requires string "k"`);
    }
    const bytes = Buffer.from(jwk.k, 'base64url');
    if (meta.hmacMinBytes && bytes.byteLength < meta.hmacMinBytes) {
      throw new JwtError(
        ErrorCode.INVALID_KEY,
        `alg ${alg} requires a secret of at least ${meta.hmacMinBytes} bytes (RFC 7518 §3.2); got ${bytes.byteLength}`,
      );
    }
    return createSecretKey(bytes);
  }

  const hasPrivate = 'd' in jwk;
  if (direction === 'sign' && !hasPrivate) {
    throw new JwtError(
      ErrorCode.INVALID_KEY,
      `alg ${alg}: sign requires a private JWK (with "d"); got a public-only JWK`,
    );
  }

  try {
    const keyObj = hasPrivate
      ? createPrivateKey({ key: /** @type {any} */ (jwk), format: 'jwk' })
      : createPublicKey({ key: /** @type {any} */ (jwk), format: 'jwk' });
    _assertRsaModulus(keyObj, meta, alg);
    return keyObj;
  } catch (err) {
    if (err instanceof JwtError) {
      throw err;
    }
    throw new JwtError(
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
