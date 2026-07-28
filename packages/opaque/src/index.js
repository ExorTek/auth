/**
 * Opaque reference tokens — a random, unstructured token that carries
 * no payload of its own. The only way to learn anything about it is to
 * look it up in the store `create` wrote it to. Ships RFC 7662
 * (introspection) and RFC 7009 (revocation) HTTP handlers on top.
 */

import { hash } from '@exortek/crypto';
import { parseDuration } from '@exortek/shared/duration';
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
  const expiresAt = expiresIn !== undefined ? new Date(now + parseDuration(expiresIn)) : undefined;

  await store.set(hashedToken, metadata ?? {}, { expiresIn });

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
 * @param {unknown} raw  A Node `http.ServerResponse`, or a Fastify
 *   `Reply` (unwrapped via `.raw`).
 * @param {number} status
 * @param {Record<string, unknown>} body
 */
function respondJson(raw, status, body) {
  const target = /** @type {any} */ (raw).raw ?? raw;
  target.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  target.end(JSON.stringify(body));
}

/**
 * @typedef {object} HandlerOptions
 * @property {OpaqueStore} store
 * @property {import('@exortek/crypto').HashAlgorithm} [hashAlgo='sha256']
 * @property {string} [tokenField='token']  Field read from the parsed request body.
 * @property {(err: unknown) => void} [onError]  Called if `store.get`/`store.delete`
 *   throws. The handler still responds with the no-oracle default so the endpoint
 *   never leaks store-health signals — this hook exists so the app can still log
 *   the failure.
 */

/**
 * RFC 7662 §2.2 token introspection endpoint. Always responds `200`
 * — `active: false` for a missing/malformed/unknown/revoked token, so
 * a caller can't distinguish "invalid" from "doesn't exist" by status
 * code alone. `req.body` must already be parsed (Express `json()`
 * middleware, Fastify's built-in JSON parsing).
 *
 * @param {HandlerOptions} options
 * @returns {(req: any, res: any) => Promise<void>}
 */
export function introspectionHandler(options) {
  assertObject(options, 'introspectionHandler.options');
  const { store, hashAlgo = 'sha256', tokenField = 'token', onError } = options;
  assertObject(store, 'introspectionHandler.options.store');

  return async function introspection(req, res) {
    const token = req?.body?.[tokenField];
    if (typeof token !== 'string' || token.length === 0) {
      respondJson(res, 200, { active: false });
      return;
    }
    try {
      const result = await verify(token, { store, hashAlgo });
      if (!result.valid) {
        respondJson(res, 200, { active: false });
        return;
      }
      respondJson(res, 200, { ...result.metadata, active: true });
    } catch (err) {
      // Preserve the no-oracle contract even under store failure — a
      // 500 with a stack page would tell the caller "the store is
      // reachable at X" and betray which endpoint hit the DB.
      if (typeof onError === 'function') onError(err);
      respondJson(res, 200, { active: false });
    }
  };
}

/**
 * RFC 7009 §2.2 token revocation endpoint. Always responds `200` with
 * an empty body — regardless of whether the token existed — so the
 * endpoint can't be used to probe token validity.
 *
 * @param {HandlerOptions} options
 * @returns {(req: any, res: any) => Promise<void>}
 */
export function revocationHandler(options) {
  assertObject(options, 'revocationHandler.options');
  const { store, hashAlgo = 'sha256', tokenField = 'token', onError } = options;
  assertObject(store, 'revocationHandler.options.store');

  return async function revocation(req, res) {
    const token = req?.body?.[tokenField];
    try {
      if (typeof token === 'string' && token.length > 0) {
        await revoke(token, { store, hashAlgo });
      }
    } catch (err) {
      if (typeof onError === 'function') onError(err);
    }
    respondJson(res, 200, {});
  };
}

export { OpaqueError, ErrorCode } from './errors.js';
