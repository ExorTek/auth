/**
 * JWS JSON Serialization — general (multi-signature) and flattened
 * (single-signature) forms per RFC 7515 §7.2.
 *
 * The signing input for each signature is identical to what compact
 * serialisation produces: `BASE64URL(protected).BASE64URL(payload)`.
 * The JSON form just carries the parts as fields instead of a
 * dot-joined string, and lets a single payload be signed by multiple
 * keys with different algorithms.
 */

import { JwsError, ErrorCode } from './internal/errors.js';
import { assertNonEmptyString } from './internal/guards.js';
import { lookup as lookupAlg } from './internal/algorithms.js';
import { normalizeKey } from './internal/keys.js';
import { assertSignSide as assertCritSign, assertVerifySide as assertCritVerify } from './internal/crit.js';
import { encode as b64uEncode, decode as b64uDecode, decodeJson as b64uDecodeJson } from './internal/base64url.js';
import { resolveKey } from './internal/resolver.js';

/**
 * @typedef {import('./internal/keys.js').KeyInput} KeyInput
 * @typedef {import('./internal/resolver.js').KeyResolverFn} KeyResolverFn
 * @typedef {import('./sign.js').SignOptions} SignOptions
 * @typedef {import('./verify.js').VerifyOptions} VerifyOptions
 *
 * @typedef {Object} SignSpec
 * @property {KeyInput} key
 * @property {SignOptions & { unprotected?: Record<string, unknown> }} options
 *
 * @typedef {Object} JsonSignature
 * @property {string} protected
 * @property {Record<string, unknown>} [header]
 * @property {string} signature
 *
 * @typedef {Object} GeneralJws
 * @property {string} payload
 * @property {JsonSignature[]} signatures
 *
 * @typedef {Object} FlattenedJws
 * @property {string} payload
 * @property {string} protected
 * @property {Record<string, unknown>} [header]
 * @property {string} signature
 */

/**
 * Sign a payload with one or more keys and return a JWS JSON
 * serialisation. A single signer yields the flattened form; multiple
 * signers yield the general form.
 *
 * @param {unknown} payload
 * @param {SignSpec[]} signers
 * @returns {Promise<GeneralJws | FlattenedJws>}
 */
export async function signJson(payload, signers) {
  if (!Array.isArray(signers) || signers.length === 0) {
    throw new JwsError(
      ErrorCode.INVALID_ARGUMENT,
      'signJson: signers must be a non-empty array of { key, options } specs',
    );
  }

  const bytes = _payloadBytes(payload);
  const encPayload = bytes.toString('base64url');

  const signatures = await Promise.all(signers.map((spec, index) => _signOne(spec, encPayload, index)));

  if (signatures.length === 1) {
    const only = signatures[0];
    /** @type {FlattenedJws} */
    const flat = {
      payload: encPayload,
      protected: only.protected,
      signature: only.signature,
    };
    if (only.header) {
      flat.header = only.header;
    }
    return flat;
  }

  return { payload: encPayload, signatures };
}

/**
 * Verify a JWS JSON serialisation (general or flattened). Returns the
 * first signature that verifies; the rest are attempted so a JWS with
 * one good signature + one tampered signature still verifies. Setting
 * every signature to fail (or providing no resolvable key for any of
 * them) raises {@link ErrorCode.INVALID_SIGNATURE}.
 *
 * @param {GeneralJws | FlattenedJws} jwsJson
 * @param {KeyInput | KeyInput[] | KeyResolverFn} keyish
 * @param {VerifyOptions} options
 * @returns {Promise<{ header: Record<string, unknown>, payload: unknown, kid?: string, matchedSignatureIndex: number }>}
 */
export async function verifyJson(jwsJson, keyish, options) {
  const allowlist = _requireAllowlist(options);
  if (jwsJson == null || typeof jwsJson !== 'object' || Array.isArray(jwsJson)) {
    throw new JwsError(ErrorCode.INVALID_TOKEN, 'verifyJson: expected a JWS JSON object (general or flattened)');
  }
  const encPayload = /** @type {any} */ (jwsJson).payload;
  if (typeof encPayload !== 'string') {
    throw new JwsError(ErrorCode.INVALID_TOKEN, 'verifyJson: `payload` must be a base64url string');
  }

  const sigList = _extractSignatures(jwsJson);
  if (sigList.length === 0) {
    throw new JwsError(ErrorCode.INVALID_TOKEN, 'verifyJson: JWS carries no signatures');
  }

  const bytes = b64uDecode(encPayload);
  /** @type {JwsError | null} */
  let lastError = null;
  for (let i = 0; i < sigList.length; i++) {
    try {
      const result = await _verifyOne(sigList[i], encPayload, bytes, keyish, allowlist, options);
      return { ...result, matchedSignatureIndex: i };
    } catch (err) {
      if (err instanceof JwsError) {
        lastError = err;
        continue;
      }
      throw err;
    }
  }
  throw (
    lastError ||
    new JwsError(ErrorCode.INVALID_SIGNATURE, `verifyJson: no signature verified (tried ${sigList.length})`)
  );
}

// sign helpers

/**
 * @param {SignSpec} spec
 * @param {string} encPayload
 * @param {number} index
 * @returns {Promise<JsonSignature>}
 */
async function _signOne(spec, encPayload, index) {
  if (spec == null || typeof spec !== 'object' || spec.options == null) {
    throw new JwsError(
      ErrorCode.INVALID_ARGUMENT,
      `signJson: signer[${index}] must be an object with { key, options }`,
    );
  }
  const { key, options } = spec;
  assertNonEmptyString(options.alg, `signJson.signers[${index}].options.alg`);
  const alg = options.alg;
  if (alg === 'none') {
    throw new JwsError(
      ErrorCode.ALGORITHM_NONE_FORBIDDEN,
      `signJson: signer[${index}] alg "none" is refused unconditionally (RFC 8725 §3.1)`,
    );
  }
  const meta = lookupAlg(alg);
  const keyObj = await normalizeKey(key, alg, 'sign');

  const protectedHeader = _buildProtectedHeader(alg, options);
  assertCritSign(protectedHeader.crit, protectedHeader);
  const encProtected = Buffer.from(JSON.stringify(protectedHeader), 'utf8').toString('base64url');

  const signingInput = Buffer.from(`${encProtected}.${encPayload}`, 'utf8');
  const signature = await meta.sign(keyObj, signingInput);

  /** @type {JsonSignature} */
  const out = {
    protected: encProtected,
    signature: b64uEncode(signature),
  };
  const unprotected = /** @type {any} */ (options).unprotected;
  if (unprotected !== undefined) {
    if (unprotected == null || typeof unprotected !== 'object' || Array.isArray(unprotected)) {
      throw new JwsError(
        ErrorCode.INVALID_ARGUMENT,
        `signJson: signer[${index}] unprotected header must be a JSON object`,
      );
    }
    out.header = /** @type {Record<string, unknown>} */ (unprotected);
  }
  return out;
}

/**
 * @param {string} alg
 * @param {SignOptions & { unprotected?: Record<string, unknown> }} options
 * @returns {Record<string, unknown>}
 */
function _buildProtectedHeader(alg, options) {
  /** @type {Record<string, unknown>} */
  const header = { alg };
  if (options.kid !== undefined) {
    header.kid = options.kid;
  }
  if (options.header && typeof options.header === 'object') {
    for (const [k, v] of Object.entries(options.header)) {
      if (k === 'alg') {
        continue;
      }
      header[k] = v;
    }
  }
  if (options.crit !== undefined) {
    header.crit = Array.isArray(options.crit) ? [...options.crit] : options.crit;
  }
  return header;
}

/**
 * @param {unknown} payload
 * @returns {Buffer}
 */
function _payloadBytes(payload) {
  if (payload === undefined) {
    throw new JwsError(ErrorCode.INVALID_PAYLOAD, 'signJson: payload is required');
  }
  if (Buffer.isBuffer(payload)) {
    return payload;
  }
  if (payload instanceof Uint8Array) {
    return Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength);
  }
  if (typeof payload === 'string') {
    return Buffer.from(payload, 'utf8');
  }
  return Buffer.from(JSON.stringify(payload), 'utf8');
}

// verify helpers

/**
 * @param {VerifyOptions | undefined} options
 * @returns {string[]}
 */
function _requireAllowlist(options) {
  if (options == null || typeof options !== 'object') {
    throw new JwsError(
      ErrorCode.MISSING_ALG_ALLOWLIST,
      'verifyJson: options.alg is required — pass an explicit allowlist array',
    );
  }
  const allow = options.alg;
  if (!Array.isArray(allow) || allow.length === 0 || allow.some(a => typeof a !== 'string')) {
    throw new JwsError(
      ErrorCode.MISSING_ALG_ALLOWLIST,
      'verifyJson: options.alg must be a non-empty array of algorithm identifier strings',
    );
  }
  return /** @type {string[]} */ (allow);
}

/**
 * @param {GeneralJws | FlattenedJws} jwsJson
 * @returns {JsonSignature[]}
 */
function _extractSignatures(jwsJson) {
  const asAny = /** @type {any} */ (jwsJson);
  if (Array.isArray(asAny.signatures)) {
    for (const [i, s] of asAny.signatures.entries()) {
      if (s == null || typeof s !== 'object') {
        throw new JwsError(ErrorCode.INVALID_TOKEN, `verifyJson: signatures[${i}] must be an object`);
      }
    }
    return /** @type {JsonSignature[]} */ (asAny.signatures);
  }
  if (typeof asAny.signature === 'string') {
    return [
      {
        protected: /** @type {string} */ (asAny.protected),
        header: asAny.header,
        signature: asAny.signature,
      },
    ];
  }
  throw new JwsError(
    ErrorCode.INVALID_TOKEN,
    'verifyJson: expected either `signatures` array (general form) or `signature` string (flattened form)',
  );
}

/**
 * @param {JsonSignature} sig
 * @param {string} encPayload
 * @param {Buffer} payloadBytes
 * @param {KeyInput | KeyInput[] | KeyResolverFn} keyish
 * @param {string[]} allowlist
 * @param {VerifyOptions} options
 */
async function _verifyOne(sig, encPayload, payloadBytes, keyish, allowlist, options) {
  if (typeof sig.protected !== 'string' || typeof sig.signature !== 'string') {
    throw new JwsError(
      ErrorCode.INVALID_TOKEN,
      'verifyJson: signature entry must include `protected` and `signature` strings',
    );
  }
  const header = /** @type {Record<string, unknown>} */ (b64uDecodeJson(sig.protected, 'header'));
  if (header == null || typeof header !== 'object' || Array.isArray(header)) {
    throw new JwsError(ErrorCode.INVALID_HEADER, 'verifyJson: protected header must be a JSON object');
  }
  if (typeof header.alg !== 'string') {
    throw new JwsError(ErrorCode.INVALID_HEADER, 'verifyJson: protected header must carry an `alg` string');
  }
  const alg = /** @type {string} */ (header.alg);
  if (alg === 'none') {
    throw new JwsError(
      ErrorCode.ALGORITHM_NONE_FORBIDDEN,
      'verifyJson: signature uses alg "none" — refused unconditionally',
    );
  }
  if (!allowlist.includes(alg)) {
    throw new JwsError(
      ErrorCode.ALGORITHM_MISMATCH,
      `verifyJson: signature alg ${JSON.stringify(alg)} is not in the caller's allowlist`,
    );
  }

  assertCritVerify(header.crit, header, options.knownCriticalHeaders);

  const meta = lookupAlg(alg);
  const keyObj = await resolveKey(keyish, header, alg);

  const signingInput = Buffer.from(`${sig.protected}.${encPayload}`, 'utf8');
  const signature = b64uDecode(sig.signature);
  const ok = await meta.verify(keyObj, signingInput, signature);
  if (!ok) {
    throw new JwsError(ErrorCode.INVALID_SIGNATURE, `verifyJson: signature does not match (alg=${alg})`);
  }

  return {
    header,
    payload: _decodeJsonPayload(payloadBytes),
    kid: /** @type {string | undefined} */ (header.kid),
  };
}

/**
 * Try JSON first, fall back to raw bytes — matches the compact verify
 * behaviour.
 *
 * @param {Buffer} bytes
 */
function _decodeJsonPayload(bytes) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    return bytes;
  }
}
