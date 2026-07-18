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
 * The KeyObject / Buffer / JWK core comes from
 * `@exortek/shared/normalize-key`; only the string / PEM branch stays
 * jwt-local.
 *
 * Enforces per-alg kty compatibility and RSA modulus / HMAC minimum
 * lengths (RFC 7518 §3.2, §3.3, §3.5) — alg-confusion attacks surface
 * as a clean {@link ErrorCode.INVALID_KEY} at the key boundary rather
 * than a cryptic Node error deep in `crypto.sign`.
 */

import { createPrivateKey, createPublicKey, createSecretKey, X509Certificate } from 'node:crypto';

import { createKeyNormalizer } from '@exortek/shared/normalize-key';

import { JwtError, ErrorCode } from './errors.js';
import { lookup as lookupAlg } from './algorithms.js';

/**
 * @typedef {import('node:crypto').KeyObject | Buffer | Uint8Array | string | Record<string, unknown>} KeyInput
 */

const shared = createKeyNormalizer({
  ErrorClass: JwtError,
  ErrorCode,
  lookupAlg,
});

/**
 * @param {KeyInput} key
 * @param {string} alg
 * @param {'sign' | 'verify'} direction
 * @returns {Promise<import('node:crypto').KeyObject>}
 */
export async function normalizeKey(key, alg, direction) {
  if (typeof key === 'string') {
    return _fromString(key, lookupAlg(alg), direction, alg);
  }
  const out = await shared.normalizeCore(key, alg, direction);
  if (out !== null) {
    return out;
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
 * @param {import('@exortek/shared/normalize-key').AlgDescriptor} meta
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
        shared.assertRsaModulus(cert.publicKey, meta, alg);
        shared.assertPemKeyType(cert.publicKey, meta, alg);
        return cert.publicKey;
      }
      if (key.includes('PRIVATE KEY-----')) {
        const k = createPrivateKey({ key, format: 'pem' });
        shared.assertKeyObject(k, meta, direction, alg);
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
        shared.assertPemKeyType(k, meta, alg);
        shared.assertRsaModulus(k, meta, alg);
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
