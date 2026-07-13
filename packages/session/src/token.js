import { randomBytes } from 'node:crypto';
import { seal, unseal } from '@exortek/crypto';
import { CryptoError, ErrorCode as CryptoErrorCode } from '@exortek/crypto';
import { SessionError, ErrorCode } from './errors.js';

/**
 * @typedef {object} SessionTokenPayload
 * @property {string} sid           Server-side session ID (opaque, from CSPRNG).
 * @property {string | null} uid    User ID (or `null` for anonymous sessions).
 * @property {object} claims        Free-form claims — roles, tenant, etc.
 * @property {number} iat           Issued-at (ms epoch).
 * @property {number} exp           Absolute expiry (ms epoch).
 * @property {number} [freshAt]     Last fresh-auth timestamp (sudo mode).
 * @property {string} [fp]          Fingerprint hash (IP + UA), when `bindTo` is enabled.
 * @property {string} [imp]         Admin user ID that started the impersonation.
 */

/**
 * Generate a fresh session ID — 128 bits of CSPRNG entropy, base64url.
 * Comfortably beyond the birthday-collision bound for any realistic
 * user base.
 *
 * @returns {string}
 */
export function generateSessionId() {
  return randomBytes(16).toString('base64url');
}

/**
 * Encode a session payload as a sealed (AES-256-GCM authenticated)
 * opaque token. Wraps `@exortek/crypto.seal` — the TTL of the seal
 * matches the payload's own `exp - now`, so the transport layer refuses
 * to open an expired token before we even parse it.
 *
 * @param {SessionTokenPayload} payload
 * @param {string | Buffer | Uint8Array} secret
 * @param {{ now?: number }} [options]
 * @returns {string}    base64url token.
 */
export function encodeToken(payload, secret, options = {}) {
  const now = options.now ?? Date.now();
  const ttlMs = payload.exp - now;
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new SessionError(
      ErrorCode.INVALID_ARGUMENT,
      `encodeToken: payload.exp must be in the future; got ${payload.exp} for now=${now}`,
    );
  }
  // seal takes ttl in seconds (or a duration string). Round up to avoid
  // an off-by-one where the token expires 1 ms before the intended
  // `exp`.
  const ttlSeconds = Math.max(1, Math.ceil(ttlMs / 1000));
  return seal(payload, secret, { ttl: ttlSeconds, now });
}

/**
 * Decode + authenticate a session token. Returns the payload on
 * success, or a structured failure via {@link SessionError}. Callers
 * generally want to catch and translate to `null` — the manager does
 * this so `verify(req)` never throws for a wrong-shape stored value.
 *
 * `secret` may be a single key or an array `[newest, …older]` for
 * secret rotation. `crypto.unseal` walks the list; the first that
 * authenticates wins.
 *
 * @param {string} token
 * @param {string | Buffer | Uint8Array | Array<string | Buffer | Uint8Array>} secret
 * @param {{ now?: number }} [options]
 * @returns {SessionTokenPayload}
 * @throws {SessionError} — with `INVALID_TOKEN` / `EXPIRED` / `INVALID_ARGUMENT`.
 */
export function decodeToken(token, secret, options = {}) {
  if (typeof token !== 'string' || token.length === 0) {
    throw new SessionError(ErrorCode.INVALID_TOKEN, 'decodeToken: token must be a non-empty string');
  }
  let opened;
  try {
    opened = unseal(token, secret, { now: options.now });
  } catch (cause) {
    if (cause instanceof CryptoError) {
      if (cause.code === CryptoErrorCode.TOKEN_EXPIRED) {
        throw new SessionError(ErrorCode.EXPIRED, 'session token has expired', { cause });
      }
      // TOKEN_MALFORMED / TOKEN_TAMPERED / INVALID_ARGUMENT all collapse
      // into INVALID_TOKEN here — do not distinguish, they leak nothing
      // useful to the caller and treating them uniformly avoids
      // fingerprinting an attacker's probes.
      throw new SessionError(ErrorCode.INVALID_TOKEN, 'session token failed authentication', { cause });
    }
    throw cause;
  }
  const payload = opened.payload;
  if (!payload || typeof payload !== 'object' || typeof payload.sid !== 'string') {
    throw new SessionError(ErrorCode.INVALID_TOKEN, 'session token payload is not a valid session record');
  }
  return payload;
}
