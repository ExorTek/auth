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

import { isObject } from '@exortek/shared/predicates';

import { JwtError, ErrorCode } from './internal/errors.js';
import { assertString } from './internal/guards.js';
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

  if (opts.maxAge !== undefined) {
    if (typeof payload.iat !== 'number') {
      throw new JwtError(ErrorCode.MISSING_CLAIM, 'verify: `maxAge` requires `iat` in the token; got none');
    }
    const maxAgeSec = parseDuration(opts.maxAge);
    if (payload.iat + maxAgeSec + tolerance < now) {
      throw new JwtError(
        ErrorCode.TOKEN_TOO_OLD,
        `verify: token is older than maxAge (${opts.maxAge}); iat=${new Date(payload.iat * 1000).toISOString()}`,
      );
    }
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

  if (payload.sub !== undefined && typeof payload.sub !== 'string') {
    throw new JwtError(
      ErrorCode.INVALID_SUBJECT,
      'verify: `sub` claim must be a case-sensitive string (RFC 7519 §4.1.2)',
    );
  }
  if (opts.subject !== undefined) {
    assertString(opts.subject, 'verify.options.subject');
    if (payload.sub !== opts.subject) {
      throw new JwtError(
        ErrorCode.INVALID_SUBJECT,
        `verify: token sub ${JSON.stringify(payload.sub)} does not match expected ${JSON.stringify(opts.subject)}`,
      );
    }
  }

  if (opts.issuer !== undefined) {
    if (payload.iss === undefined) {
      throw new JwtError(ErrorCode.INVALID_ISSUER, 'verify: token is missing an `iss` claim');
    }
    const ok = await _matchClaim(opts.issuer, /** @type {string} */ (payload.iss));
    if (!ok) {
      throw new JwtError(
        ErrorCode.INVALID_ISSUER,
        `verify: token iss ${JSON.stringify(payload.iss)} does not match the caller's expected issuer`,
      );
    }
  }

  if (opts.audience !== undefined) {
    const claimed = Array.isArray(payload.aud)
      ? /** @type {string[]} */ (payload.aud)
      : payload.aud !== undefined
        ? [/** @type {string} */ (payload.aud)]
        : [];
    if (claimed.length === 0) {
      throw new JwtError(ErrorCode.INVALID_AUDIENCE, 'verify: token is missing an `aud` claim');
    }
    for (const value of claimed) {
      if (typeof value !== 'string') {
        throw new JwtError(
          ErrorCode.INVALID_AUDIENCE,
          `verify: token \`aud\` entries must be strings; got ${JSON.stringify(value)}`,
        );
      }
    }
    let matched = false;
    for (const value of claimed) {
      if (await _matchClaim(opts.audience, value)) {
        matched = true;
        break;
      }
    }
    if (!matched) {
      throw new JwtError(
        ErrorCode.INVALID_AUDIENCE,
        `verify: token aud [${claimed.map(a => JSON.stringify(a)).join(', ')}] does not match the caller's expected audience`,
      );
    }
  }

  if (opts.nonce !== undefined) {
    assertString(opts.nonce, 'verify.options.nonce');
    if (payload.nonce !== opts.nonce) {
      throw new JwtError(ErrorCode.INVALID_NONCE, 'verify: token `nonce` does not match the caller-supplied value');
    }
  }

  if (opts.requiredClaims && opts.requiredClaims.length > 0) {
    for (const name of opts.requiredClaims) {
      if (!(name in payload) || payload[name] === undefined) {
        throw new JwtError(
          ErrorCode.MISSING_CLAIM,
          `verify: required claim ${JSON.stringify(name)} is missing from the payload`,
        );
      }
    }
  }

  if (opts.requiredScopes && opts.requiredScopes.length > 0) {
    const scopeSet = _extractScopes(payload);
    for (const required of opts.requiredScopes) {
      if (!scopeSet.has(required)) {
        throw new JwtError(
          ErrorCode.INSUFFICIENT_SCOPE,
          `verify: token is missing required scope ${JSON.stringify(required)}`,
        );
      }
    }
  }
}

/**
 * Match a single claim value against a matcher. Matcher can be a string
 * (exact), a RegExp (test), an array of either, or an async predicate
 * function returning boolean.
 *
 * @param {string | string[] | RegExp | Array<string | RegExp> | ((claimed: string) => boolean | Promise<boolean>)} matcher
 * @param {string} value
 * @returns {Promise<boolean>}
 */
async function _matchClaim(matcher, value) {
  if (typeof matcher === 'function') {
    return Boolean(await matcher(value));
  }
  if (typeof matcher === 'string') {
    return matcher === value;
  }
  if (matcher instanceof RegExp) {
    return matcher.test(value);
  }
  if (Array.isArray(matcher)) {
    for (const entry of matcher) {
      if (typeof entry === 'string' && entry === value) {
        return true;
      }
      if (entry instanceof RegExp && entry.test(value)) {
        return true;
      }
    }
    return false;
  }
  throw new JwtError(
    ErrorCode.INVALID_ARGUMENT,
    'claims matcher must be string | RegExp | array of either | async predicate function',
  );
}

/**
 * Extract OAuth2 scopes from the payload. Standard OAuth2 encodes them
 * as space-separated `scope` (RFC 8693 §4.2), but some deployments use
 * an array `scp`. Support both.
 *
 * @param {Record<string, unknown>} payload
 * @returns {Set<string>}
 */
function _extractScopes(payload) {
  if (typeof payload.scope === 'string') {
    return new Set(payload.scope.split(/\s+/).filter(Boolean));
  }
  if (Array.isArray(payload.scp)) {
    return new Set(/** @type {unknown[]} */ (payload.scp).filter(x => typeof x === 'string'));
  }
  return new Set();
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
  if (isObject(spec)) {
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
