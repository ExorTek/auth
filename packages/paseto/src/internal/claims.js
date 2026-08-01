/**
 * PASETO registered claims (§Registered Claims). Unlike JWT's numeric
 * `NumericDate`, PASETO time claims (`exp` / `nbf` / `iat`) are **ISO
 * 8601 datetime strings**. This module stamps them on the way out and
 * validates them (plus `iss` / `sub` / `aud`) on the way in.
 */

import { parseDuration } from '@exortek/shared/duration';
import { isString, isObject, isArray } from '@exortek/shared/predicates';

import { PasetoError, ErrorCode } from './errors.js';
import { invalidArgument } from './guards.js';

const asMs = (value, name) => {
  if (value === undefined) {
    return 0;
  }
  try {
    return parseDuration(value);
  } catch (err) {
    throw invalidArgument(`${name}: ${err.message}`, { cause: err });
  }
};

/**
 * Return a copy of `payload` with the registered claims applied. Values
 * already present on `payload` are never overwritten — an explicit claim
 * always wins over an option.
 *
 * @param {Record<string, unknown>} payload
 * @param {object} [options]
 * @param {string | number} [options.expiresIn]   duration → `exp`
 * @param {string | number} [options.notBefore]   duration → `nbf`
 * @param {boolean} [options.iat=true]            stamp `iat` = now
 * @param {string} [options.issuer]               → `iss`
 * @param {string} [options.subject]              → `sub`
 * @param {string} [options.audience]             → `aud`
 * @param {string} [options.jti]                  → `jti`
 * @param {Date} [now=new Date()]
 * @returns {Record<string, unknown>}
 */
export function applyClaims(payload, options = {}, now = new Date()) {
  const out = { ...payload };
  const nowMs = now.getTime();

  if (options.iat !== false && out.iat === undefined) {
    out.iat = new Date(nowMs).toISOString();
  }
  if (options.expiresIn !== undefined && out.exp === undefined) {
    out.exp = new Date(nowMs + asMs(options.expiresIn, 'expiresIn')).toISOString();
  }
  if (options.notBefore !== undefined && out.nbf === undefined) {
    out.nbf = new Date(nowMs + asMs(options.notBefore, 'notBefore')).toISOString();
  }
  for (const [opt, claim] of [
    ['issuer', 'iss'],
    ['subject', 'sub'],
    ['audience', 'aud'],
    ['jti', 'jti'],
  ]) {
    if (options[opt] !== undefined && out[claim] === undefined) {
      out[claim] = options[opt];
    }
  }
  return out;
}

/** Parse an ISO 8601 claim into epoch ms, or throw INVALID_TOKEN. */
function claimTime(value, claim) {
  const ms = Date.parse(value);
  if (!isString(value) || Number.isNaN(ms)) {
    throw new PasetoError(ErrorCode.INVALID_TOKEN, `${claim} claim is not a valid ISO 8601 datetime`);
  }
  return ms;
}

/**
 * Validate the registered claims on a decoded payload. Throws a typed
 * `PasetoError` on the first failure.
 *
 * @param {Record<string, unknown>} payload
 * @param {object} [options]
 * @param {string | number} [options.clockTolerance=0]  slack for exp/nbf
 * @param {boolean} [options.ignoreExp=false]
 * @param {boolean} [options.ignoreNbf=false]
 * @param {string} [options.issuer]     required `iss`
 * @param {string} [options.subject]    required `sub`
 * @param {string} [options.audience]   required `aud` (matches string or array member)
 * @param {Date} [now=new Date()]
 */
export function validateClaims(payload, options = {}, now = new Date()) {
  if (!isObject(payload)) {
    return;
  }
  const nowMs = now.getTime();
  const tolerance = asMs(options.clockTolerance, 'clockTolerance');

  if (!options.ignoreExp && payload.exp !== undefined) {
    if (nowMs - tolerance >= claimTime(payload.exp, 'exp')) {
      throw new PasetoError(ErrorCode.TOKEN_EXPIRED, 'token has expired (exp)');
    }
  }
  if (!options.ignoreNbf && payload.nbf !== undefined) {
    if (nowMs + tolerance < claimTime(payload.nbf, 'nbf')) {
      throw new PasetoError(ErrorCode.NOT_YET_VALID, 'token is not yet valid (nbf)');
    }
  }

  if (options.issuer !== undefined && payload.iss !== options.issuer) {
    throw new PasetoError(ErrorCode.CLAIM_MISMATCH, `iss mismatch: expected ${options.issuer}`);
  }
  if (options.subject !== undefined && payload.sub !== options.subject) {
    throw new PasetoError(ErrorCode.CLAIM_MISMATCH, `sub mismatch: expected ${options.subject}`);
  }
  if (options.audience !== undefined) {
    const aud = payload.aud;
    const ok = isArray(aud) ? aud.includes(options.audience) : aud === options.audience;
    if (!ok) {
      throw new PasetoError(ErrorCode.CLAIM_MISMATCH, `aud mismatch: expected ${options.audience}`);
    }
  }
}
