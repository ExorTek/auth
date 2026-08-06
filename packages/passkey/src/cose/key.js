/**
 * COSE Key Map ↔ Node `KeyObject`, plus the small algorithm table
 * WebAuthn actually uses.
 *
 * Reference: RFC 8152 §7 (COSE common labels) + §13 (key type
 * parameters); RFC 8230 §4 (RSA COSE parameters).
 *
 * WebAuthn credential public keys arrive as CBOR-decoded `Map`s
 * (integer keys) — see `../cbor/decode.js`. We convert into a JWK
 * (RFC 7517 shape) and hand it to `crypto.createPublicKey({ key, format: 'jwk' })`.
 * Node handles the ASN.1 export from there.
 */

import { createPublicKey } from 'node:crypto';
import { base64url } from '@exortek/crypto/encode';
import { PasskeyError, ErrorCode } from '../errors.js';

// COSE common labels (RFC 8152 §7.1)
const LABEL = /** @type {const} */ ({
  KTY: 1,
  ALG: 3,
});

const KTY = /** @type {const} */ ({
  OKP: 1,
  EC2: 2,
  RSA: 3,
});

// EC2 parameters (RFC 8152 §13.1)
const EC2 = /** @type {const} */ ({
  CRV: -1,
  X: -2,
  Y: -3,
});

// OKP parameters (RFC 8152 §13.2)
const OKP = /** @type {const} */ ({
  CRV: -1,
  X: -2,
});

// RSA parameters (RFC 8230 §4)
const RSA = /** @type {const} */ ({
  N: -1,
  E: -2,
});

// Minimum acceptable RSA modulus size (in bytes). FIDO2 and every
// modern WebAuthn platform require at least 2048 bits; anything
// smaller is a red flag we reject at import time so a malformed or
// downgrade-attack COSE key never reaches Node's JWK importer.
const MIN_RSA_MODULUS_BYTES = 256;

// EC curves (RFC 8152 §13.1)
const EC_CURVE = /** @type {const} */ ({
  1: 'P-256',
  2: 'P-384',
  3: 'P-521',
});

// OKP curves (RFC 8152 §13.2)
const OKP_CURVE = /** @type {const} */ ({
  4: 'X25519',
  5: 'X448',
  6: 'Ed25519',
  7: 'Ed448',
});

/**
 * COSE algorithm identifiers WebAuthn implementations actually use.
 * Anything outside this table is rejected at import time — a
 * silently-accepted RS1 (SHA-1 with RSA) would be a real risk.
 *
 * Keyed by COSE alg id. Each entry carries:
 *   - `name`: human label for error messages
 *   - `nodeAlgorithm`: string for `crypto.verify(algorithm, ...)`;
 *      `null` means "no digest string, use the key alone" (Ed*).
 *   - `verifyOptions`: extras to spread into `crypto.verify` call
 *      site (PSS padding / saltLength, ECDSA DER encoding).
 */
export const ALGORITHMS = Object.freeze({
  // Elliptic curve — signatures are ASN.1 DER encoded per COSE §8.1.
  '-7': {
    name: 'ES256',
    nodeAlgorithm: 'SHA256',
    curve: 'P-256',
    verifyOptions: { dsaEncoding: 'der' },
  },
  '-35': {
    name: 'ES384',
    nodeAlgorithm: 'SHA384',
    curve: 'P-384',
    verifyOptions: { dsaEncoding: 'der' },
  },
  '-36': {
    name: 'ES512',
    nodeAlgorithm: 'SHA512',
    curve: 'P-521',
    verifyOptions: { dsaEncoding: 'der' },
  },

  // Edwards-curve — Ed25519 / Ed448 verify without a separate digest.
  '-8': { name: 'EdDSA', nodeAlgorithm: null, curve: 'Ed25519', verifyOptions: {} },

  // RSA PKCS#1 v1.5 — RS256 is the WebAuthn common case for Windows Hello / TPM.
  '-257': { name: 'RS256', nodeAlgorithm: 'RSA-SHA256', verifyOptions: {} },
  '-258': { name: 'RS384', nodeAlgorithm: 'RSA-SHA384', verifyOptions: {} },
  '-259': { name: 'RS512', nodeAlgorithm: 'RSA-SHA512', verifyOptions: {} },

  // RSASSA-PSS — same digest, PSS padding, salt length = hash length
  // (RFC 8230 §3 requires the salt length to equal the hash length).
  '-37': {
    name: 'PS256',
    nodeAlgorithm: 'SHA256',
    verifyOptions: { padding: 6 /* RSA_PKCS1_PSS_PADDING */, saltLength: 32 },
  },
  '-38': {
    name: 'PS384',
    nodeAlgorithm: 'SHA384',
    verifyOptions: { padding: 6, saltLength: 48 },
  },
  '-39': {
    name: 'PS512',
    nodeAlgorithm: 'SHA512',
    verifyOptions: { padding: 6, saltLength: 64 },
  },
});

/**
 * Default supportedAlgorithms list used by `registration.begin` and
 * enforced by `finish` when the caller doesn't override — the set
 * every reasonable authenticator in 2026 implements.
 */
export const DEFAULT_SUPPORTED_ALGORITHMS = Object.freeze([-8, -7, -257]);

/**
 * Convert a Node `Buffer`/`Uint8Array` to a base64url string using
 * `@exortek/crypto`'s encoder.
 *
 * @param {Uint8Array} bytes
 */
function b64u(bytes) {
  return base64url.encode(bytes);
}

/**
 * Import a COSE Key Map (as returned by our CBOR decoder) into a
 * Node `KeyObject`.
 *
 * @param {Map<number, unknown>} coseKey
 * @returns {{
 *   algorithm: number,
 *   name: string,
 *   publicKey: import('node:crypto').KeyObject,
 *   jwk: Record<string, unknown>,
 * }}
 */
export function importCoseKey(coseKey) {
  if (!(coseKey instanceof Map)) {
    throw new PasskeyError(ErrorCode.INVALID_ARGUMENT, 'cose: expected a Map (decoded COSE Key)');
  }

  const kty = coseKey.get(LABEL.KTY);
  const alg = coseKey.get(LABEL.ALG);

  if (typeof alg !== 'number') {
    throw new PasskeyError(ErrorCode.INVALID_ARGUMENT, 'cose: missing or non-integer alg (label 3)');
  }
  const params = ALGORITHMS[String(alg)];
  if (!params) {
    throw new PasskeyError(ErrorCode.UNSUPPORTED_ALGORITHM, `cose: unsupported algorithm ${alg}`);
  }

  let jwk;
  if (kty === KTY.EC2) {
    jwk = ec2ToJwk(coseKey, params);
  } else if (kty === KTY.OKP) {
    jwk = okpToJwk(coseKey, params);
  } else if (kty === KTY.RSA) {
    jwk = rsaToJwk(coseKey);
  } else {
    throw new PasskeyError(
      ErrorCode.PUBLIC_KEY_UNSUPPORTED,
      `cose: unsupported kty ${String(kty)} (want 1=OKP, 2=EC2, 3=RSA)`,
    );
  }

  // Node's JWK importer performs its own parameter checks — a
  // mismatched curve / short coordinate throws here rather than at
  // verify-time.
  const publicKey = createPublicKey({ key: jwk, format: 'jwk' });

  return { algorithm: alg, name: params.name, publicKey, jwk };
}

function ec2ToJwk(coseKey, params) {
  const crvId = coseKey.get(EC2.CRV);
  const crv = EC_CURVE[crvId];
  if (!crv) {
    throw new PasskeyError(ErrorCode.PUBLIC_KEY_UNSUPPORTED, `cose EC2: unsupported curve ${String(crvId)}`);
  }
  if (params.curve && params.curve !== crv) {
    throw new PasskeyError(
      ErrorCode.PUBLIC_KEY_UNSUPPORTED,
      `cose EC2: curve ${crv} does not match algorithm ${params.name} (expects ${params.curve})`,
    );
  }
  const x = coseKey.get(EC2.X);
  const y = coseKey.get(EC2.Y);
  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) {
    throw new PasskeyError(
      ErrorCode.PUBLIC_KEY_UNSUPPORTED,
      'cose EC2: x and y must be byte strings (compressed points not supported)',
    );
  }
  const size = crv === 'P-256' ? 32 : crv === 'P-384' ? 48 : 66;
  if (x.byteLength !== size || y.byteLength !== size) {
    throw new PasskeyError(ErrorCode.PUBLIC_KEY_UNSUPPORTED, `cose EC2: ${crv} coordinates must be ${size} bytes each`);
  }
  return { kty: 'EC', crv, x: b64u(x), y: b64u(y) };
}

function okpToJwk(coseKey, params) {
  const crvId = coseKey.get(OKP.CRV);
  const crv = OKP_CURVE[crvId];
  if (!crv) {
    throw new PasskeyError(ErrorCode.PUBLIC_KEY_UNSUPPORTED, `cose OKP: unsupported curve ${String(crvId)}`);
  }
  // Only signature curves land in WebAuthn credential keys.
  if (crv !== 'Ed25519' && crv !== 'Ed448') {
    throw new PasskeyError(ErrorCode.PUBLIC_KEY_UNSUPPORTED, `cose OKP: curve ${crv} is not a signature curve`);
  }
  if (params.curve && params.curve !== crv) {
    throw new PasskeyError(
      ErrorCode.PUBLIC_KEY_UNSUPPORTED,
      `cose OKP: curve ${crv} does not match algorithm ${params.name} (expects ${params.curve})`,
    );
  }
  const x = coseKey.get(OKP.X);
  if (!(x instanceof Uint8Array)) {
    throw new PasskeyError(ErrorCode.PUBLIC_KEY_UNSUPPORTED, 'cose OKP: x must be a byte string');
  }
  // Ed25519 = 32 bytes; Ed448 = 57 bytes.
  const expected = crv === 'Ed25519' ? 32 : 57;
  if (x.byteLength !== expected) {
    throw new PasskeyError(ErrorCode.PUBLIC_KEY_UNSUPPORTED, `cose OKP: ${crv} public key must be ${expected} bytes`);
  }
  return { kty: 'OKP', crv, x: b64u(x) };
}

function rsaToJwk(coseKey) {
  const n = coseKey.get(RSA.N);
  const e = coseKey.get(RSA.E);
  if (!(n instanceof Uint8Array) || !(e instanceof Uint8Array)) {
    throw new PasskeyError(ErrorCode.PUBLIC_KEY_UNSUPPORTED, 'cose RSA: n and e must be byte strings');
  }
  if (n.byteLength < MIN_RSA_MODULUS_BYTES) {
    throw new PasskeyError(
      ErrorCode.PUBLIC_KEY_UNSUPPORTED,
      `cose RSA: modulus is ${n.byteLength * 8} bits, minimum ${MIN_RSA_MODULUS_BYTES * 8}`,
    );
  }
  // WebAuthn RSA keys are unsigned big-endian integers — Node's JWK
  // importer expects them stripped of a leading zero pad if present,
  // but Node <20 tolerated both; keep the raw form for portability.
  return { kty: 'RSA', n: b64u(n), e: b64u(e) };
}

/**
 * Look up the algorithm parameters for a COSE alg id. Throws if the
 * id is not in the supported table.
 *
 * @param {number} algId
 */
export function algorithmForId(algId) {
  const params = ALGORITHMS[String(algId)];
  if (!params) {
    throw new PasskeyError(ErrorCode.UNSUPPORTED_ALGORITHM, `cose: unsupported algorithm ${algId}`);
  }
  return params;
}
