import { createHash } from 'node:crypto';

/**
 * Read the client IP from a request. Honours the "trust proxy" contract
 * of Fastify / Express (`req.ip`); otherwise falls back to the socket
 * peer address. Never trusts `X-Forwarded-For` unless the framework
 * already resolved it into `req.ip` — matches the default distrust of
 * XFF in `@exortek/security`.
 *
 * @param {any} req
 * @returns {string | undefined}
 */
export function readIp(req) {
  if (!req) {
    return undefined;
  }
  if (typeof req.ip === 'string' && req.ip.length > 0) {
    return req.ip;
  }
  const socket = req.socket ?? req.connection;
  if (socket && typeof socket.remoteAddress === 'string') {
    return socket.remoteAddress;
  }
  return undefined;
}

/**
 * Read the User-Agent header from a request, tolerant of both Node
 * `IncomingMessage` (headers dict) and WHATWG `Request` (`.headers.get`).
 *
 * @param {any} req
 * @returns {string | undefined}
 */
export function readUserAgent(req) {
  const headers = req?.headers;
  if (!headers) {
    return undefined;
  }
  const raw = typeof headers.get === 'function' ? headers.get('user-agent') : headers['user-agent'];
  if (typeof raw !== 'string' || raw.length === 0) {
    return undefined;
  }
  // Cap at 512 chars — a UA over that is either a broken client or an
  // attacker attempting a store-fill attack.
  return raw.length > 512 ? raw.slice(0, 512) : raw;
}

/**
 * Derive a compact fingerprint from the pieces the caller opted into.
 * Uses SHA-256 truncated to 16 bytes (128 bits) — enough to make
 * collisions unrealistic without bloating the sealed cookie payload.
 *
 * `bindTo` is an array — order MUST be stable across issue and verify.
 * We always concatenate in the same canonical order regardless of the
 * caller's array order.
 *
 * @param {any} req
 * @param {ReadonlyArray<'ip' | 'ua'>} bindTo
 * @returns {string | undefined}    base64url hash, or `undefined` when no bindTo entry resolved.
 */
export function computeFingerprint(req, bindTo) {
  if (!Array.isArray(bindTo) || bindTo.length === 0) {
    return undefined;
  }
  const parts = [];
  const set = new Set(bindTo);
  // Canonical order: ip first, then ua. Keeps the hash stable even if
  // the caller flips the array between issue and verify.
  if (set.has('ip')) {
    const ip = readIp(req);
    parts.push(`ip:${ip ?? ''}`);
  }
  if (set.has('ua')) {
    const ua = readUserAgent(req);
    parts.push(`ua:${ua ?? ''}`);
  }
  if (parts.every(p => p.endsWith(':'))) {
    return undefined;
  }
  return createHash('sha256').update(parts.join('\n')).digest('base64url').slice(0, 22);
}
