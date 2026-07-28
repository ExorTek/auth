/**
 * Opaque reference tokens — a random, unstructured token that carries
 * no payload of its own. The only way to learn anything about it is to
 * look it up in the store `create` wrote it to. Ships RFC 7662
 * (introspection) and RFC 7009 (revocation) HTTP handlers on top.
 */

import { hash } from '@exortek/crypto';
import { parseDuration } from '@exortek/shared/duration';
import { isNonEmptyString, isFunction } from '@exortek/shared/predicates';
import { generate } from './token.js';
import { assertObject, assertNonEmptyString } from './internal/guards.js';

export { generate } from './token.js';

/**
 * @typedef {object} OpaqueStore
 * @property {(key: string, value: Record<string, unknown>, options?: { expiresIn?: string | number }) => Promise<void>} set
 * @property {(key: string) => Promise<Record<string, unknown> | null>} get
 *   Must return `null` once the entry's TTL has passed — expiry is the
 *   store's responsibility, not this package's.
 * @property {(key: string) => Promise<boolean>} delete
 */

/**
 * @typedef {import('./token.js').GenerateOptions & {
 *   store: OpaqueStore,
 *   expiresIn?: string | number,
 *   metadata?: Record<string, unknown>,
 *   hashAlgo?: import('@exortek/crypto').HashAlgorithm,
 *   now?: number,
 * }} CreateOptions
 */

function hashToken(token, hashAlgo) {
  return /** @type {string} */ (hash(token, { algo: hashAlgo }));
}

/**
 * Mint a new opaque token and persist its metadata under the token's
 * hash. The wire token is returned once — only its hash lives in the
 * store, mirroring how a leaked DB row can't be turned back into a
 * usable token.
 *
 * @param {CreateOptions} options
 * @returns {Promise<{ token: string, hash: string, expiresAt?: Date }>}
 */
export async function create(options) {
  assertObject(options, 'create.options');
  const { store, expiresIn, metadata, hashAlgo = 'sha256', now = Date.now(), ...tokenOptions } = options;
  assertObject(store, 'create.options.store');

  const token = generate(tokenOptions);
  const hashedToken = hashToken(token, hashAlgo);
  // Parse once — stores also accept a number, so a single ms value keeps
  // the returned expiresAt and the store's TTL calculation in lockstep.
  const expiresMs = expiresIn !== undefined ? parseDuration(expiresIn) : undefined;
  const expiresAt = expiresMs !== undefined ? new Date(now + expiresMs) : undefined;

  await store.set(hashedToken, metadata ?? {}, { expiresIn: expiresMs });

  return { token, hash: hashedToken, expiresAt };
}

/**
 * @typedef {object} VerifyOptions
 * @property {OpaqueStore} store
 * @property {import('@exortek/crypto').HashAlgorithm} [hashAlgo='sha256']
 */

/**
 * Look up a token by its hash. Never throws for a bad/expired/unknown
 * token — that's a normal outcome, not a programmer error.
 *
 * @param {string} token
 * @param {VerifyOptions} options
 * @returns {Promise<{ valid: true, metadata: Record<string, unknown> } | { valid: false, reason: 'not_found' }>}
 */
export async function verify(token, options) {
  assertNonEmptyString(token, 'verify.token');
  assertObject(options, 'verify.options');
  const { store, hashAlgo = 'sha256' } = options;
  assertObject(store, 'verify.options.store');

  const record = await store.get(hashToken(token, hashAlgo));
  if (record === null || record === undefined) {
    return { valid: false, reason: 'not_found' };
  }
  return { valid: true, metadata: record };
}

/**
 * Delete a token's store entry — it fails every subsequent `verify`.
 * Idempotent: revoking twice, or a token that never existed, both
 * just return `false`.
 *
 * @param {string} token
 * @param {VerifyOptions} options
 * @returns {Promise<boolean>}
 */
export async function revoke(token, options) {
  assertNonEmptyString(token, 'revoke.token');
  assertObject(options, 'revoke.options');
  const { store, hashAlgo = 'sha256' } = options;
  assertObject(store, 'revoke.options.store');

  return store.delete(hashToken(token, hashAlgo));
}

/**
 * Log-safe representation — first 4 / last 4 characters, everything
 * else replaced with an ellipsis.
 *
 * @param {string} token
 * @returns {string}
 */
export function mask(token) {
  assertNonEmptyString(token, 'mask.token');
  if (token.length <= 8) {
    return '*'.repeat(token.length);
  }
  return `${token.slice(0, 4)}…${token.slice(-4)}`;
}

/**
 * @typedef {object} HandlerResult
 * @property {number} status   HTTP status the caller should respond with.
 * @property {Record<string, unknown> | null} body  JSON body to serialize,
 *   or `null` when there is no body (a 204 revocation response).
 * @property {Record<string, string>} headers  Response headers the
 *   caller should merge onto their response. Includes the RFC-mandated
 *   defaults (`Content-Type: application/json` on JSON responses,
 *   `Cache-Control: no-store`, `Pragma: no-cache` — RFC 6749 §5.1
 *   applied to sensitive token responses). The caller is free to add
 *   more (CORS, request-id, whatever) before writing them out.
 */

const JSON_HEADERS = Object.freeze({
  'Content-Type': 'application/json',
  'Cache-Control': 'no-store',
  Pragma: 'no-cache',
});

const NO_CONTENT_HEADERS = Object.freeze({
  'Cache-Control': 'no-store',
  Pragma: 'no-cache',
});

/**
 * @typedef {object} HandlerOptions
 * @property {OpaqueStore} store
 * @property {import('@exortek/crypto').HashAlgorithm} [hashAlgo='sha256']
 * @property {string} [tokenField='token']  Field read from the parsed request body.
 * @property {(err: unknown) => void} [onError]  Called if `store.get`/`store.delete`
 *   throws. The handler still returns the no-oracle default so the endpoint
 *   never leaks store-health signals — this hook exists so the app can still
 *   log the failure.
 */

/**
 * RFC 7662 §2.2 token introspection. Returns a `{ status, body }` pair
 * the caller writes to their framework's response however they want —
 * add CORS headers, wrap in an envelope, whatever. The status is always
 * `200`, and `body.active` is `false` for a missing/malformed/unknown/
 * revoked token, so the caller can't distinguish "invalid" from "doesn't
 * exist" by status code alone (RFC 7662 §2.2 anti-oracle guidance).
 *
 * `req.body` must already be parsed (Express `json()` middleware,
 * Fastify's built-in JSON parsing).
 *
 * @param {HandlerOptions} options
 * @returns {(req: any) => Promise<HandlerResult>}
 */
export function introspectionHandler(options) {
  assertObject(options, 'introspectionHandler.options');
  const { store, hashAlgo = 'sha256', tokenField = 'token', onError } = options;
  assertObject(store, 'introspectionHandler.options.store');

  return async function introspection(req) {
    const token = req?.body?.[tokenField];
    if (!isNonEmptyString(token)) {
      return { status: 200, body: { active: false }, headers: { ...JSON_HEADERS } };
    }
    try {
      const result = await verify(token, { store, hashAlgo });
      const body = result.valid ? { ...result.metadata, active: true } : { active: false };
      return { status: 200, body, headers: { ...JSON_HEADERS } };
    } catch (err) {
      // Preserve the no-oracle contract even under store failure — a
      // 500 with a stack page would tell the caller the store is reachable
      // and betray which endpoint hit the DB.
      if (isFunction(onError)) {
        onError(err);
      }
      return { status: 200, body: { active: false }, headers: { ...JSON_HEADERS } };
    }
  };
}

/**
 * RFC 7009 §2.2 token revocation. Returns `{ status: 204, body: null }`
 * regardless of whether the token existed, so the endpoint can't be
 * used to probe token validity. The caller writes the response
 * themselves.
 *
 * @param {HandlerOptions} options
 * @returns {(req: any) => Promise<HandlerResult>}
 */
export function revocationHandler(options) {
  assertObject(options, 'revocationHandler.options');
  const { store, hashAlgo = 'sha256', tokenField = 'token', onError } = options;
  assertObject(store, 'revocationHandler.options.store');

  return async function revocation(req) {
    const token = req?.body?.[tokenField];
    try {
      if (isNonEmptyString(token)) {
        await revoke(token, { store, hashAlgo });
      }
    } catch (err) {
      if (isFunction(onError)) {
        onError(err);
      }
    }
    return { status: 204, body: null, headers: { ...NO_CONTENT_HEADERS } };
  };
}

export { OpaqueError, ErrorCode } from './errors.js';
