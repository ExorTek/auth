/**
 * `@exortek/apikey` — Stripe-style prefixed API keys with HMAC-hashed
 * storage, scope allowlists, and opt-in pepper rotation.
 *
 * See the README for the full API and worked examples.
 */

import { parseDuration } from '@exortek/shared/duration';
import {
  isArray,
  isBytes,
  isBuffer,
  isFunction,
  isNumber,
  isObject,
  isString,
  isUndefined,
} from '@exortek/shared/predicates';

import { ApiKeyError, ErrorCode } from './errors.js';
import { invalidArgument } from './internal/guards.js';

/** Prefix-specific factory so `assertPrefix` throws `INVALID_PREFIX`,
 *  not the generic `INVALID_ARGUMENT`. Callers can `catch (err)` and
 *  branch on `err.code === ErrorCode.INVALID_PREFIX` — a specific
 *  code beats a generic one for pinpointing config drift. */
const invalidPrefix = msg => new ApiKeyError(ErrorCode.INVALID_PREFIX, msg);
import { hasAll } from './scopes.js';
import {
  assertPrefix,
  candidateHashesFor,
  hashesMatch,
  mask as maskKey,
  mint,
  parseApiKey as parseKey,
} from './token.js';

export { ApiKeyError, ErrorCode } from './errors.js';
export { covers, hasAll, hasAny } from './scopes.js';
export { parseApiKey, mask } from './token.js';

const MIN_PEPPER_BYTES = 16;

/**
 * @typedef {object} ApiKeyRecord
 * @property {string} id                      Plaintext lookup key (128-bit b64u).
 * @property {string} hash                    Storage hash of the secret (43-char b64u).
 * @property {string} prefix                  The prefix the key was minted with.
 * @property {string} userId
 * @property {string[]} scopes
 * @property {string} [name]                  Human label ("Production Backend").
 * @property {string} [environment]           `'live'` / `'test'` / caller-defined.
 * @property {Record<string, unknown>} [metadata]
 * @property {number} createdAt               ms epoch.
 * @property {number} [expiresAt]             ms epoch; absent = no expiry.
 * @property {number} [revokedAt]             ms epoch when the record was revoked.
 * @property {string} [revokedReason]
 * @property {number} [lastUsedAt]            ms epoch of the last successful verify.
 * @property {number} [pepperVersion]         Index into the peppers array that was used at mint. 0 = newest.
 */

/**
 * @typedef {object} ApiKeyStore
 * @property {(record: ApiKeyRecord) => Promise<void>} put
 * @property {(id: string) => Promise<ApiKeyRecord | null>} getById
 * @property {(id: string, patch: Partial<ApiKeyRecord>) => Promise<ApiKeyRecord | null>} update
 * @property {(id: string, reason?: string) => Promise<boolean>} revoke
 * @property {(userId: string, reason?: string) => Promise<number>} revokeAllForUser
 * @property {(userId: string) => Promise<ApiKeyRecord[]>} listByUser
 */

/**
 * @typedef {object} CreateApiKeyOptions
 * @property {string} prefix                       Stripe-style; `sk_live`, `pk_test`, `svc_prod_v2`.
 * @property {string} userId
 * @property {string[]} scopes
 * @property {string} [name]
 * @property {string} [environment]
 * @property {Record<string, unknown>} [metadata]
 * @property {string | number} [expiresIn]         `'1y'` / `'30d'` / ms integer. Omit for no expiry.
 * @property {ApiKeyStore} store
 * @property {(Buffer | Uint8Array | string)[]} [peppers]
 *   Newest first. Each ≥16 bytes. Omit for plain SHA-256 storage.
 * @property {number} [now]                        Override `Date.now()` for testing.
 */

/**
 * @typedef {object} CreateApiKeyResult
 * @property {string} key       Wire token — show ONCE to the caller and never again.
 * @property {string} id        Plaintext lookup key; safe to store / log / display.
 * @property {ApiKeyRecord} record  What was persisted to the store.
 */

/**
 * @typedef {object} VerifyApiKeyOptions
 * @property {ApiKeyStore} store
 * @property {(Buffer | Uint8Array | string)[]} [peppers]
 * @property {string[]} [requiredScopes]
 * @property {string} [expectedPrefix]             Reject a valid key whose prefix differs.
 * @property {boolean} [updateLastUsed=false]      Bump `lastUsedAt` on success (one extra store write).
 * @property {number} [now]
 */

/**
 * @typedef {'malformed' | 'not_found' | 'expired' | 'revoked'
 *   | 'bad_secret' | 'prefix_mismatch' | 'missing_scope'
 *   | 'store_unavailable'} VerifyApiKeyFailureReason
 */

/**
 * @typedef {{
 *   valid: true,
 *   id: string,
 *   userId: string,
 *   scopes: string[],
 *   prefix: string,
 *   name?: string,
 *   environment?: string,
 *   metadata?: Record<string, unknown>,
 *   needsRehash?: boolean,
 * } | { valid: false, reason: VerifyApiKeyFailureReason }} VerifyApiKeyResult
 */

/**
 * Mint a new API key. The wire `key` is returned once — the caller
 * MUST show it to the end user immediately and never persist it in
 * the clear (only the storage `hash` inside the returned `record` is
 * safe to keep).
 *
 * @param {CreateApiKeyOptions} options
 * @returns {Promise<CreateApiKeyResult>}
 */
export async function createApiKey(options) {
  if (!isObject(options)) {
    throw invalidArgument('createApiKey.options must be an object');
  }
  const prefix = assertPrefix(options.prefix, 'createApiKey.options.prefix', invalidPrefix);
  const userId = _requireString(options.userId, 'createApiKey.options.userId');
  const scopes = _requireStringArray(options.scopes, 'createApiKey.options.scopes');
  _assertStore(options.store, 'createApiKey.options.store');
  _assertStringOrUndef(options.name, 'createApiKey.options.name');
  _assertStringOrUndef(options.environment, 'createApiKey.options.environment');
  if (!isUndefined(options.metadata) && !isObject(options.metadata)) {
    throw invalidArgument('createApiKey.options.metadata must be a plain object when provided');
  }
  const peppers = _normalizePeppers(options.peppers, 'createApiKey.options.peppers');
  const now = _now(options.now);
  let expiresAt;
  if (!isUndefined(options.expiresIn)) {
    let ttlMs;
    try {
      ttlMs = parseDuration(options.expiresIn);
    } catch (err) {
      throw invalidArgument(`createApiKey.options.expiresIn: ${err.message}`, { cause: err });
    }
    if (!isNumber(ttlMs) || ttlMs <= 0) {
      throw invalidArgument(`createApiKey.options.expiresIn must resolve to a positive duration; got ${ttlMs}ms`);
    }
    expiresAt = now + ttlMs;
  }

  const newestPepper = peppers && peppers.length > 0 ? peppers[0] : null;
  const { key, id, hash } = mint(prefix, newestPepper);

  /** @type {ApiKeyRecord} */
  const record = {
    id,
    hash,
    prefix,
    userId,
    scopes: [...scopes],
    createdAt: now,
  };
  if (!isUndefined(options.name)) {
    record.name = options.name;
  }
  if (!isUndefined(options.environment)) {
    record.environment = options.environment;
  }
  if (!isUndefined(options.metadata)) {
    record.metadata = { ...options.metadata };
  }
  if (!isUndefined(expiresAt)) {
    record.expiresAt = expiresAt;
  }
  if (peppers) {
    record.pepperVersion = 0;
  }

  try {
    await options.store.put(record);
  } catch (err) {
    throw new ApiKeyError(ErrorCode.STORE_ERROR, `createApiKey.store.put failed: ${err.message}`, { cause: err });
  }
  return { key, id, record };
}

/**
 * Verify a raw API key. Returns `{ valid: true, ... }` on success, or
 * `{ valid: false, reason }` on any expected failure. Never throws on
 * a bad key — a wrong or stale key is a normal auth outcome.
 *
 * On success, callers get the stored `userId` / `scopes` / `metadata`
 * and can pass them straight to their app's auth context.
 * `needsRehash: true` in the success result signals the secret matched
 * an older pepper — call `rehashApiKey(id, options)` to silently
 * migrate storage to the newest pepper on the next natural chance.
 *
 * @param {string} rawKey
 * @param {VerifyApiKeyOptions} options
 * @returns {Promise<VerifyApiKeyResult>}
 */
export async function verifyApiKey(rawKey, options) {
  if (!isObject(options)) {
    throw invalidArgument('verifyApiKey.options must be an object');
  }
  _assertStore(options.store, 'verifyApiKey.options.store');
  const peppers = _normalizePeppers(options.peppers, 'verifyApiKey.options.peppers');
  const requiredScopes = options.requiredScopes;
  if (!isUndefined(requiredScopes) && !_isStringArray(requiredScopes)) {
    throw invalidArgument('verifyApiKey.options.requiredScopes must be a string[] when provided');
  }
  if (!isUndefined(options.expectedPrefix)) {
    assertPrefix(options.expectedPrefix, 'verifyApiKey.options.expectedPrefix', invalidPrefix);
  }

  const parsed = parseKey(rawKey);
  if (!parsed) {
    return { valid: false, reason: 'malformed' };
  }
  if (!isUndefined(options.expectedPrefix) && parsed.prefix !== options.expectedPrefix) {
    return { valid: false, reason: 'prefix_mismatch' };
  }

  let record;
  try {
    record = await options.store.getById(parsed.id);
  } catch {
    return { valid: false, reason: 'store_unavailable' };
  }
  if (!record) {
    return { valid: false, reason: 'not_found' };
  }
  const now = _now(options.now);
  if (record.revokedAt) {
    return { valid: false, reason: 'revoked' };
  }
  if (record.expiresAt && record.expiresAt <= now) {
    return { valid: false, reason: 'expired' };
  }
  if (parsed.prefix !== record.prefix) {
    // Someone submitted a key whose id belongs to a different prefix —
    // treat as bad, not merely 'prefix_mismatch', because the id half
    // was correct: the attacker guessed the id and swapped the prefix.
    return { valid: false, reason: 'prefix_mismatch' };
  }
  const { candidateHashes } = candidateHashesFor(parsed.secret, peppers);
  let matched = false;
  let matchedIndex = -1;
  for (let i = 0; i < candidateHashes.length; i++) {
    if (hashesMatch(candidateHashes[i], record.hash)) {
      matched = true;
      matchedIndex = i;
      break;
    }
  }
  if (!matched) {
    return { valid: false, reason: 'bad_secret' };
  }
  if (isArray(requiredScopes) && requiredScopes.length > 0 && !hasAll(record.scopes, requiredScopes)) {
    return { valid: false, reason: 'missing_scope' };
  }
  if (options.updateLastUsed === true) {
    // Fire-and-forget on the store side — failure to bump lastUsedAt
    // must not fail the verify itself. Await it so callers can wait
    // for consistency if they want.
    try {
      await options.store.update(parsed.id, { lastUsedAt: now });
    } catch {
      // Ignore — lastUsedAt is telemetry, not correctness.
    }
  }

  /** @type {VerifyApiKeyResult} */
  const result = {
    valid: true,
    id: record.id,
    userId: record.userId,
    scopes: record.scopes,
    prefix: record.prefix,
  };
  if (record.name) {
    result.name = record.name;
  }
  if (record.environment) {
    result.environment = record.environment;
  }
  if (record.metadata) {
    result.metadata = record.metadata;
  }
  // Peppers rotate newest-first; non-zero index means the secret
  // matched an older pepper — the storage hash should migrate.
  if (peppers && matchedIndex > 0) {
    result.needsRehash = true;
  }
  return result;
}

/**
 * Revoke an API key by id or by the raw wire key. Returns `true` if
 * a record was actually revoked, `false` if the id was unknown or
 * the record was already revoked.
 *
 * @param {string} keyOrId    Either the raw wire key or its id half.
 * @param {{ store: ApiKeyStore, reason?: string }} options
 * @returns {Promise<boolean>}
 */
export async function revokeApiKey(keyOrId, options) {
  if (!isObject(options)) {
    throw invalidArgument('revokeApiKey.options must be an object');
  }
  _assertStore(options.store, 'revokeApiKey.options.store');
  const id = _asId(keyOrId);
  if (!id) {
    return false;
  }
  return options.store.revoke(id, options.reason);
}

/**
 * Revoke every non-revoked key belonging to `userId`. Useful on
 * password reset, account termination, etc. Returns the number of
 * records actually revoked.
 *
 * @param {string} userId
 * @param {{ store: ApiKeyStore, reason?: string }} options
 * @returns {Promise<number>}
 */
export async function revokeAllForUser(userId, options) {
  if (!isObject(options)) {
    throw invalidArgument('revokeAllForUser.options must be an object');
  }
  _assertStore(options.store, 'revokeAllForUser.options.store');
  _requireString(userId, 'revokeAllForUser.userId');
  return options.store.revokeAllForUser(userId, options.reason);
}

/**
 * List every key belonging to `userId` — for a "manage API keys" UI.
 * Callers should hide the storage `hash` before rendering; only the
 * plaintext `id` is safe to display. Returns most-recently-used first
 * (falling back to createdAt) so active keys float to the top.
 *
 * @param {string} userId
 * @param {{ store: ApiKeyStore }} options
 * @returns {Promise<ApiKeyRecord[]>}
 */
export async function listApiKeys(userId, options) {
  if (!isObject(options)) {
    throw invalidArgument('listApiKeys.options must be an object');
  }
  _assertStore(options.store, 'listApiKeys.options.store');
  _requireString(userId, 'listApiKeys.userId');
  const rows = await options.store.listByUser(userId);
  if (!isArray(rows)) {
    return [];
  }
  return rows.slice().sort((a, b) => (b.lastUsedAt ?? b.createdAt) - (a.lastUsedAt ?? a.createdAt));
}

/**
 * Migrate the storage hash of an existing key to the newest pepper.
 * Requires the raw wire key (the plaintext secret is the input to the
 * new HMAC). Called opportunistically when `verifyApiKey` reports
 * `needsRehash: true`.
 *
 * @param {string} rawKey
 * @param {{ store: ApiKeyStore, peppers: (Buffer | Uint8Array | string)[] }} options
 * @returns {Promise<boolean>}
 */
export async function rehashApiKey(rawKey, options) {
  if (!isObject(options)) {
    throw invalidArgument('rehashApiKey.options must be an object');
  }
  _assertStore(options.store, 'rehashApiKey.options.store');
  const peppers = _normalizePeppers(options.peppers, 'rehashApiKey.options.peppers');
  if (!peppers || peppers.length === 0) {
    throw invalidArgument('rehashApiKey.options.peppers must be a non-empty array');
  }
  const parsed = parseKey(rawKey);
  if (!parsed) {
    return false;
  }
  const { candidateHashes } = candidateHashesFor(parsed.secret, [peppers[0]]);
  const newHash = candidateHashes[0];
  const updated = await options.store.update(parsed.id, { hash: newHash, pepperVersion: 0 });
  return Boolean(updated);
}

// ---------------------------------------------------------------------
// internals

function _now(override) {
  return isNumber(override) ? override : Date.now();
}

function _asId(keyOrId) {
  if (!isString(keyOrId)) {
    return null;
  }
  // If it looks like a full wire key, extract the id half; otherwise
  // treat the string itself as an id.
  const parsed = parseKey(keyOrId);
  return parsed ? parsed.id : keyOrId;
}

function _requireString(v, name) {
  if (!isString(v) || v.length === 0) {
    throw invalidArgument(`${name} must be a non-empty string`);
  }
  return v;
}

function _assertStringOrUndef(v, name) {
  if (!isUndefined(v) && !isString(v)) {
    throw invalidArgument(`${name} must be a string when provided`);
  }
}

function _isStringArray(v) {
  if (!isArray(v)) {
    return false;
  }
  for (const item of v) {
    if (!isString(item)) {
      return false;
    }
  }
  return true;
}

function _requireStringArray(v, name) {
  if (!_isStringArray(v) || v.length === 0) {
    throw invalidArgument(`${name} must be a non-empty string[]`);
  }
  return v;
}

function _assertStore(v, name) {
  if (
    !isObject(v) ||
    !isFunction(v.put) ||
    !isFunction(v.getById) ||
    !isFunction(v.update) ||
    !isFunction(v.revoke) ||
    !isFunction(v.revokeAllForUser) ||
    !isFunction(v.listByUser)
  ) {
    throw invalidArgument(
      `${name} must be an object with put / getById / update / revoke / revokeAllForUser / listByUser methods`,
    );
  }
}

function _normalizePeppers(input, name) {
  if (isUndefined(input)) {
    return null;
  }
  if (!isArray(input) || input.length === 0) {
    throw new ApiKeyError(ErrorCode.INVALID_PEPPER, `${name} must be a non-empty array when provided (newest first)`);
  }
  const out = [];
  for (let i = 0; i < input.length; i++) {
    const p = input[i];
    const buf = isString(p) ? Buffer.from(p, 'utf8') : isBytes(p) ? (isBuffer(p) ? p : Buffer.from(p)) : null;
    if (!buf) {
      throw new ApiKeyError(ErrorCode.INVALID_PEPPER, `${name}[${i}] must be a string / Buffer / Uint8Array`);
    }
    if (buf.length < MIN_PEPPER_BYTES) {
      throw new ApiKeyError(
        ErrorCode.INVALID_PEPPER,
        `${name}[${i}] must be at least ${MIN_PEPPER_BYTES} bytes; got ${buf.length}`,
      );
    }
    out.push(buf);
  }
  return out;
}

// Re-export mask under a friendlier name for parity with parseApiKey.
export { maskKey as maskApiKey };
