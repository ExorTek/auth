/**
 * Claims validation — RFC 7519 §4 + RFC 8725 (best practice).
 *
 * Phase-3 skeleton: `injectClaims` handles `iat` (auto or
 * `noTimestamp`), `exp` from `expiresIn`, `nbf` from `notBefore`, and
 * copies caller-supplied `iss` / `aud` / `sub` / `nonce` / `jti` onto
 * the payload. Full claims **validation** on the verify side, plus the
 * `jti` random generator, live in the claims-layer commit.
 */

import { randomBytes } from 'node:crypto';

import { JwtError, ErrorCode } from './internal/errors.js';
import { parseDuration } from './internal/duration.js';

/**
 * @typedef {Object} ClaimsOptions
 * @property {string | string[] | RegExp | Array<string | RegExp> | ((claimed: string) => boolean | Promise<boolean>)} [issuer]
 * @property {string | string[] | RegExp | Array<string | RegExp> | ((claimed: string) => boolean | Promise<boolean>)} [audience]
 * @property {string} [subject]
 * @property {string} [nonce]
 * @property {string | string[]} [typ]
 * @property {string[]} [requiredClaims]
 * @property {string[]} [requiredScopes]
 * @property {number | string} [clockTolerance]
 * @property {number | string} [maxAge]
 * @property {Date} [currentDate]
 */

/**
 * Basic claim validation shared by verify. Phase-3 skeleton runs `exp`
 * / `nbf` / `iat` checks and enforces `typ` header consistency; the
 * broader claim surface (iss / aud / sub / nonce / maxAge /
 * requiredClaims / requiredScopes) lands in the claims-layer commit.
 *
 * @param {Record<string, unknown>} payload
 * @param {Record<string, unknown>} header
 * @param {ClaimsOptions} [options]
 * @returns {Promise<void>}
 */
export async function validateClaims(payload, header, options) {
  const opts = options || {};
  const now = _now(opts.currentDate);
  const tolerance = opts.clockTolerance !== undefined ? parseDuration(opts.clockTolerance) : 0;

  if (payload.exp !== undefined) {
    if (typeof payload.exp !== 'number') {
      throw new JwtError(ErrorCode.INVALID_PAYLOAD, 'verify: `exp` claim must be a NumericDate');
    }
    if (payload.exp + tolerance < now) {
      throw new JwtError(
        ErrorCode.TOKEN_EXPIRED,
        `verify: token expired at ${new Date(payload.exp * 1000).toISOString()}`,
      );
    }
  }

  if (payload.nbf !== undefined) {
    if (typeof payload.nbf !== 'number') {
      throw new JwtError(ErrorCode.INVALID_PAYLOAD, 'verify: `nbf` claim must be a NumericDate');
    }
    if (payload.nbf - tolerance > now) {
      throw new JwtError(
        ErrorCode.TOKEN_NOT_YET_VALID,
        `verify: token not valid until ${new Date(payload.nbf * 1000).toISOString()}`,
      );
    }
  }

  if (payload.iat !== undefined && typeof payload.iat !== 'number') {
    throw new JwtError(ErrorCode.INVALID_PAYLOAD, 'verify: `iat` claim must be a NumericDate');
  }

  if (opts.typ !== undefined) {
    const expected = Array.isArray(opts.typ) ? opts.typ : [opts.typ];
    if (typeof header.typ !== 'string' || !expected.includes(header.typ)) {
      throw new JwtError(
        ErrorCode.INVALID_TYP,
        `verify: token typ ${JSON.stringify(header.typ)} not in expected [${expected.map(t => JSON.stringify(t)).join(', ')}]`,
      );
    }
  }
}

/**
 * Build the payload the signer will encode. Handles `iat` (auto unless
 * `noTimestamp`), `exp` (from `expiresIn`), `nbf` (from `notBefore`),
 * `jti` (boolean → random 16 bytes hex, object → configured size /
 * encoding, function → custom), and copies `iss` / `aud` / `sub` /
 * `nonce`. Full function-shaped `jti` + custom encoding lands in the
 * DX commit; boolean + hex works in phase 3.
 *
 * @param {Record<string, unknown>} payload
 * @param {import('./sign.js').SignOptions} options
 * @returns {Promise<Record<string, unknown>>}
 */
export async function injectClaims(payload, options) {
  const out = { ...payload };

  if (!options.noTimestamp && out.iat === undefined) {
    out.iat = _now();
  }
  if (out.iat !== undefined && typeof out.iat !== 'number') {
    throw new JwtError(ErrorCode.INVALID_PAYLOAD, 'sign: payload.iat must be a NumericDate');
  }

  if (options.expiresIn !== undefined) {
    const base = typeof out.iat === 'number' ? out.iat : _now();
    out.exp = Math.floor(base + parseDuration(options.expiresIn));
  }
  if (out.exp !== undefined && typeof out.exp !== 'number') {
    throw new JwtError(ErrorCode.INVALID_PAYLOAD, 'sign: payload.exp must be a NumericDate');
  }

  if (options.notBefore !== undefined) {
    const base = typeof out.iat === 'number' ? out.iat : _now();
    out.nbf = Math.floor(base + parseDuration(options.notBefore));
  }
  if (out.nbf !== undefined && typeof out.nbf !== 'number') {
    throw new JwtError(ErrorCode.INVALID_PAYLOAD, 'sign: payload.nbf must be a NumericDate');
  }

  if (options.issuer !== undefined) {
    out.iss = options.issuer;
  }
  if (options.audience !== undefined) {
    out.aud = options.audience;
  }
  if (options.subject !== undefined) {
    if (typeof options.subject !== 'string') {
      throw new JwtError(ErrorCode.INVALID_PAYLOAD, 'sign: `subject` must be a string (RFC 7519 §4.1.2)');
    }
    out.sub = options.subject;
  }
  if (options.nonce !== undefined) {
    if (typeof options.nonce !== 'string') {
      throw new JwtError(ErrorCode.INVALID_PAYLOAD, 'sign: `nonce` must be a string');
    }
    out.nonce = options.nonce;
  }

  if (options.jwtId !== undefined) {
    out.jti = await _resolveJti(options.jwtId);
  }

  return out;
}

/**
 * @param {import('./sign.js').SignOptions['jwtId']} spec
 * @returns {Promise<string>}
 */
async function _resolveJti(spec) {
  if (spec === true) {
    return randomBytes(16).toString('hex');
  }
  if (typeof spec === 'function') {
    const generated = await /** @type {() => string | Promise<string>} */ (spec)();
    if (typeof generated !== 'string' || generated.length === 0) {
      throw new JwtError(ErrorCode.INVALID_PAYLOAD, 'sign: jwtId function must return a non-empty string');
    }
    return generated;
  }
  if (spec && typeof spec === 'object') {
    const size = /** @type {any} */ (spec).size ?? 16;
    if (typeof size !== 'number' || size < 1 || !Number.isFinite(size)) {
      throw new JwtError(ErrorCode.INVALID_PAYLOAD, 'sign: jwtId.size must be a positive number');
    }
    const encoding = /** @type {any} */ (spec).encoding || 'hex';
    switch (encoding) {
      case 'hex':
        return randomBytes(size).toString('hex');
      case 'base64url':
        return randomBytes(size).toString('base64url');
      case 'uuid': {
        const { randomUUID } = await import('node:crypto');
        return randomUUID();
      }
      default:
        throw new JwtError(
          ErrorCode.INVALID_PAYLOAD,
          `sign: jwtId encoding ${JSON.stringify(encoding)} unsupported. Use 'hex' | 'base64url' | 'uuid' or a function.`,
        );
    }
  }
  throw new JwtError(
    ErrorCode.INVALID_PAYLOAD,
    'sign: jwtId must be `true`, a { size, encoding } object, or a `() => string` function',
  );
}

/**
 * @param {Date} [currentDate]
 * @returns {number}
 */
function _now(currentDate) {
  const ms = currentDate instanceof Date ? currentDate.getTime() : Date.now();
  return Math.floor(ms / 1000);
}
