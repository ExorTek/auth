/**
 * WebAuthn extension I/O.
 *
 * Two directions:
 *
 *   Server → browser (JSON, inside `PublicKeyCredentialCreationOptions`
 *   /  `RequestOptions`): `buildRegistrationExtensions` /
 *   `buildAuthenticationExtensions`. Binary fields become base64url
 *   strings because we ship the options as JSON to the browser (the
 *   client library then re-encodes into ArrayBuffers per the
 *   WebAuthn IDL).
 *
 *   Browser → server (results): `readClientExtensionResults` accepts
 *   the JSON `clientExtensionResults` object; `readAuthenticatorExtensions`
 *   accepts the CBOR-decoded map from `authData.extensions`. Both
 *   normalise into a friendly `{ credProps, largeBlob, prf, ... }`
 *   shape.
 *
 * References:
 *   - credProps         WebAuthn L3 §10.1.3
 *   - largeBlob         WebAuthn L3 §10.5
 *   - prf               WebAuthn L3 §10.1.4
 *   - hmac-secret       CTAP2.1 §12.5 (registration) + §12.5 (auth)
 *   - minPinLength      CTAP2.1 §12.4
 *   - credProtect       CTAP2.1 §12.1
 *   - appid / appidExclude   WebAuthn L3 §10.1.1 / §10.1.2 (U2F migration)
 */

import { base64url } from '@exortek/crypto/encode';
import { PasskeyError, ErrorCode } from '../errors.js';
import { isString, isBoolean, isInteger, isObject } from '@exortek/shared/predicates';

function b64u(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new PasskeyError(ErrorCode.EXTENSION_INVALID, 'extensions: expected Uint8Array to encode');
  }
  return base64url.encode(bytes);
}

function decodeB64u(str) {
  if (!isString(str)) {
    return null;
  }
  try {
    return new Uint8Array(base64url.decode(str));
  } catch {
    return null;
  }
}

/**
 * Build the `extensions` dict for `PublicKeyCredentialCreationOptionsJSON`.
 * Every key is optional; unknown keys pass through untouched so
 * callers can experiment with in-flight spec drafts without waiting
 * for a library update.
 *
 * @param {object} [input]
 * @param {true} [input.credProps]                  request credProps output
 * @param {{ support: 'preferred' | 'required' }} [input.largeBlob]
 * @param {{ eval?: { first: Uint8Array, second?: Uint8Array } }} [input.prf]
 * @param {true} [input.hmacCreateSecret]           request hmac-secret at register time
 * @param {true} [input.minPinLength]
 * @param {number} [input.credentialProtectionPolicy]  1/2/3 per CTAP2 §12.1
 * @param {boolean} [input.enforceCredentialProtectionPolicy]
 * @param {string} [input.appidExclude]             legacy U2F migration
 * @returns {Record<string, unknown>}
 */
export function buildRegistrationExtensions(input = {}) {
  const out = { ...input };
  if (input.credProps !== undefined) {
    if (input.credProps !== true) {
      throw new PasskeyError(ErrorCode.EXTENSION_INVALID, 'extensions.credProps must be `true` when present');
    }
    out.credProps = true;
  }
  if (input.largeBlob !== undefined) {
    const { support } = input.largeBlob;
    if (support !== 'preferred' && support !== 'required') {
      throw new PasskeyError(
        ErrorCode.EXTENSION_INVALID,
        "extensions.largeBlob.support must be 'preferred' or 'required'",
      );
    }
    out.largeBlob = { support };
  }
  if (input.prf !== undefined) {
    out.prf = encodePrfInput(input.prf);
  }
  if (input.hmacCreateSecret !== undefined) {
    if (input.hmacCreateSecret !== true) {
      throw new PasskeyError(ErrorCode.EXTENSION_INVALID, 'extensions.hmacCreateSecret must be `true` when present');
    }
    out.hmacCreateSecret = true;
  }
  if (input.minPinLength !== undefined) {
    if (input.minPinLength !== true) {
      throw new PasskeyError(ErrorCode.EXTENSION_INVALID, 'extensions.minPinLength must be `true` when present');
    }
    out.minPinLength = true;
  }
  if (input.credentialProtectionPolicy !== undefined && ![1, 2, 3].includes(input.credentialProtectionPolicy)) {
    throw new PasskeyError(
      ErrorCode.EXTENSION_INVALID,
      'extensions.credentialProtectionPolicy must be 1, 2, or 3 (CTAP2 §12.1)',
    );
  }
  if (input.appidExclude !== undefined && !isString(input.appidExclude)) {
    throw new PasskeyError(ErrorCode.EXTENSION_INVALID, 'extensions.appidExclude must be a string');
  }
  return out;
}

/**
 * Build the `extensions` dict for `PublicKeyCredentialRequestOptionsJSON`.
 *
 * @param {object} [input]
 * @param {{ read?: true, write?: Uint8Array }} [input.largeBlob]
 * @param {{ eval?: { first: Uint8Array, second?: Uint8Array },
 *          evalByCredential?: Record<string, { first: Uint8Array, second?: Uint8Array }> }} [input.prf]
 * @param {{ salt1: Uint8Array, salt2?: Uint8Array }} [input.hmacGetSecret]
 * @param {string} [input.appid]
 * @returns {Record<string, unknown>}
 */
export function buildAuthenticationExtensions(input = {}) {
  const out = { ...input };
  if (input.largeBlob !== undefined) {
    const lb = {};
    if (input.largeBlob.read !== undefined) {
      if (input.largeBlob.read !== true) {
        throw new PasskeyError(ErrorCode.EXTENSION_INVALID, 'extensions.largeBlob.read must be `true` when present');
      }
      lb.read = true;
    }
    if (input.largeBlob.write !== undefined) {
      lb.write = b64u(input.largeBlob.write);
    }
    if (lb.read && lb.write !== undefined) {
      throw new PasskeyError(
        ErrorCode.EXTENSION_INVALID,
        'extensions.largeBlob: read and write are mutually exclusive per WebAuthn L3 §10.5',
      );
    }
    out.largeBlob = lb;
  }
  if (input.prf !== undefined) {
    out.prf = encodePrfInput(input.prf);
  }
  if (input.hmacGetSecret !== undefined) {
    const { salt1, salt2 } = input.hmacGetSecret;
    if (!(salt1 instanceof Uint8Array) || salt1.byteLength !== 32) {
      throw new PasskeyError(
        ErrorCode.EXTENSION_INVALID,
        'extensions.hmacGetSecret.salt1 must be a 32-byte Uint8Array (CTAP2 §12.5)',
      );
    }
    const out2 = { salt1: b64u(salt1) };
    if (salt2 !== undefined) {
      if (!(salt2 instanceof Uint8Array) || salt2.byteLength !== 32) {
        throw new PasskeyError(
          ErrorCode.EXTENSION_INVALID,
          'extensions.hmacGetSecret.salt2 must be a 32-byte Uint8Array',
        );
      }
      out2.salt2 = b64u(salt2);
    }
    out.hmacGetSecret = out2;
  }
  if (input.appid !== undefined && !isString(input.appid)) {
    throw new PasskeyError(ErrorCode.EXTENSION_INVALID, 'extensions.appid must be a string');
  }
  return out;
}

function encodePrfInput(prf) {
  const out = {};
  if (prf.eval !== undefined) {
    out.eval = encodePrfValues(prf.eval);
  }
  if (prf.evalByCredential !== undefined) {
    const map = {};
    for (const [id, vals] of Object.entries(prf.evalByCredential)) {
      map[id] = encodePrfValues(vals);
    }
    out.evalByCredential = map;
  }
  return out;
}

function encodePrfValues({ first, second }) {
  if (!(first instanceof Uint8Array)) {
    throw new PasskeyError(ErrorCode.EXTENSION_INVALID, 'extensions.prf.eval.first must be a Uint8Array');
  }
  const out = { first: b64u(first) };
  if (second !== undefined) {
    if (!(second instanceof Uint8Array)) {
      throw new PasskeyError(
        ErrorCode.EXTENSION_INVALID,
        'extensions.prf.eval.second must be a Uint8Array when present',
      );
    }
    out.second = b64u(second);
  }
  return out;
}

/**
 * Normalise the client-provided `clientExtensionResults` JSON.
 *
 * Binary fields (`largeBlob.blob`, `prf.results.first/second`) come
 * in as base64url strings; we decode them to `Uint8Array`. Unknown
 * keys are surfaced verbatim under `raw` so callers can inspect them
 * without waiting on us to name every draft extension.
 *
 * ⚠ `out.raw` is the client's original object, unbounded and
 * untrusted. Callers who log or persist the normalised extension
 * record should treat `raw` as attacker-controlled input — decide
 * whether to strip it before storing, and never render it as-is.
 *
 * @param {Record<string, unknown> | undefined | null} results
 * @returns {Record<string, unknown>}
 */
export function readClientExtensionResults(results) {
  if (results === undefined || results === null) {
    return {};
  }
  if (!isObject(results)) {
    throw new PasskeyError(ErrorCode.EXTENSION_INVALID, 'extensions: clientExtensionResults must be an object');
  }

  const out = {};

  if (isObject(results.credProps)) {
    out.credProps = { rk: results.credProps.rk === true };
  }

  if (isObject(results.largeBlob)) {
    const lb = {};
    if (isBoolean(results.largeBlob.supported)) {
      lb.supported = results.largeBlob.supported;
    }
    if (isString(results.largeBlob.blob)) {
      const decoded = decodeB64u(results.largeBlob.blob);
      if (!decoded) {
        throw new PasskeyError(ErrorCode.EXTENSION_INVALID, 'extensions.largeBlob.blob is not valid base64url');
      }
      lb.blob = decoded;
    }
    if (results.largeBlob.written !== undefined) {
      lb.written = results.largeBlob.written === true;
    }
    out.largeBlob = lb;
  }

  if (isObject(results.prf)) {
    const prf = {};
    if (isBoolean(results.prf.enabled)) {
      prf.enabled = results.prf.enabled;
    }
    if (isObject(results.prf.results)) {
      const r = {};
      if (isString(results.prf.results.first)) {
        const first = decodeB64u(results.prf.results.first);
        if (!first) {
          throw new PasskeyError(ErrorCode.EXTENSION_INVALID, 'extensions.prf.results.first is not valid base64url');
        }
        r.first = first;
      }
      if (isString(results.prf.results.second)) {
        const second = decodeB64u(results.prf.results.second);
        if (!second) {
          throw new PasskeyError(ErrorCode.EXTENSION_INVALID, 'extensions.prf.results.second is not valid base64url');
        }
        r.second = second;
      }
      prf.results = r;
    }
    out.prf = prf;
  }

  if (isBoolean(results.appid)) {
    out.appid = results.appid;
  }
  if (isBoolean(results.appidExclude)) {
    out.appidExclude = results.appidExclude;
  }

  out.raw = results;
  return out;
}

/**
 * Normalise the authenticator-produced extensions map (from
 * `authData.extensions`, a CBOR `Map`).
 *
 * @param {Map<unknown, unknown> | null | undefined} map
 * @returns {Record<string, unknown>}
 */
export function readAuthenticatorExtensions(map) {
  if (map === null || map === undefined) {
    return {};
  }
  if (!(map instanceof Map)) {
    throw new PasskeyError(ErrorCode.EXTENSION_INVALID, 'extensions: authenticator extensions must be a Map');
  }

  const out = {};

  // CTAP2 §12.5 hmac-secret output: bytes (32 or 64) or absent.
  if (map.has('hmac-secret')) {
    const v = map.get('hmac-secret');
    if (v instanceof Uint8Array) {
      out.hmacSecret = v;
    } else if (v === true) {
      // Registration-time confirmation from some authenticators.
      out.hmacSecret = true;
    }
  }

  // CTAP2 §12.4 minPinLength: uint.
  if (map.has('minPinLength')) {
    const v = map.get('minPinLength');
    if (typeof v === 'number' && isInteger(v) && v >= 0) {
      out.minPinLength = v;
    }
  }

  // CTAP2 §12.1 credProtect policy echoed back.
  if (map.has('credProtect')) {
    const v = map.get('credProtect');
    if (typeof v === 'number' && [1, 2, 3].includes(v)) {
      out.credProtect = v;
    }
  }

  // "hmac-secret-mc" (make credential result) and other draft
  // extensions come back untouched under `raw`.
  const raw = {};
  for (const [k, v] of map) {
    raw[isString(k) ? k : String(k)] = v;
  }
  out.raw = raw;

  return out;
}
