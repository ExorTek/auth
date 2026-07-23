/**
 * `@exortek/magic-link` — passwordless email-link auth.
 *
 * The package ships tokens; you ship emails. Wire the result of
 * `createMagicLink` into your mail driver (Sendgrid / Resend / SES /
 * SMTP — the choice stays yours) and expose `verifyMagicLink` behind
 * whatever `/auth/verify` route your app already has. See the README
 * for worked examples.
 */

import { parseDuration } from '@exortek/shared/duration';
import { isBytes, isBuffer, isFunction, isNumber, isObject, isString, isUndefined } from '@exortek/shared/predicates';

import { MagicLinkError, ErrorCode } from './errors.js';
import { invalidArgument } from './internal/guards.js';
import { DEFAULT_PREFIX, assertPrefix, decode, hashEmailValue, newId, sign } from './token.js';

export { MagicLinkError, ErrorCode } from './errors.js';
export { DEFAULT_PREFIX, hashEmailValue } from './token.js';

const MIN_SECRET_BYTES = 32;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const invalidPrefix = msg => new MagicLinkError(ErrorCode.INVALID_PREFIX, msg);

/**
 * @typedef {object} MagicLinkRecord
 * @property {string} id
 * @property {string} email
 * @property {number} createdAt          ms epoch.
 * @property {number} expiresAt          ms epoch.
 * @property {number} [consumedAt]       ms epoch; set on successful consume.
 * @property {string} [redirectTo]       Where the caller wants the user routed after verify.
 * @property {Record<string, unknown>} [metadata]
 */

/**
 * @typedef {object} MagicLinkStore
 * @property {(record: MagicLinkRecord) => Promise<void>} put
 * @property {(id: string) => Promise<MagicLinkRecord | null>} getById
 * @property {(id: string) => Promise<boolean>} consume
 *   Atomic compare-and-set. Returns `true` when this call marked the
 *   record consumed for the first time; `false` on every subsequent
 *   call (including when the record doesn't exist / already consumed).
 * @property {(email: string, ttlMs: number) => Promise<{ count: number }>} [incrRate]
 *   Optional per-email rate-limit counter. First call for a fresh
 *   key returns `{ count: 1 }`; subsequent calls before expiry return
 *   the incremented count. Required only when the caller opts in via
 *   `maxPerEmail`.
 * @property {(email: string) => Promise<MagicLinkRecord[]>} [listByEmail]
 * @property {(email: string) => Promise<number>} [revokeByEmail]
 */

/**
 * @typedef {object} CreateMagicLinkOptions
 * @property {string | Buffer | Uint8Array} secret
 *   HMAC-SHA256 secret. **≥ 32 bytes.** A string is interpreted as UTF-8.
 * @property {string} email
 * @property {string} baseUrl
 *   The URL your `/auth/verify` route lives at. The returned `url`
 *   appends `?token=<token>` (or `&token=` if `baseUrl` already has a
 *   query string).
 * @property {string | number} expiresIn      `'15m'` / `'1h'` / ms integer.
 * @property {string} [redirectTo]
 *   Stored in the record and returned on a successful verify — never
 *   embedded in the token / URL, so it cannot be tampered with by
 *   editing the link.
 * @property {Record<string, unknown>} [metadata]
 * @property {boolean} [hashEmail=true]
 *   When true (default), the token's payload carries
 *   `eh = SHA-256(secret ‖ email)` so `verifyMagicLink` can
 *   short-circuit a wrong-email reject before touching the store.
 *   Turn off only when you need a shorter payload and are OK with
 *   the extra store hit + slightly larger surface for token
 *   substitution attacks.
 * @property {string} [prefix='mlink_v1']
 *   Wire-format prefix. Same value must be used at verify time.
 * @property {MagicLinkStore} store
 * @property {{ count: number, window: string | number }} [maxPerEmail]
 *   Opt-in per-email rate limit. `store.incrRate` is required when
 *   this is set. When the count exceeds `count` inside the window,
 *   throws `MagicLinkError` with `code: RATE_LIMITED`.
 * @property {number} [now]                   Override `Date.now()` for testing.
 */

/**
 * @typedef {object} CreateMagicLinkResult
 * @property {string} token       The compact token — embed in the emailed URL.
 * @property {string} url         `baseUrl` + `?token=<token>` — ready to email.
 * @property {string} id          Store lookup key; safe to log.
 * @property {number} expiresAt   ms epoch.
 * @property {MagicLinkRecord} record  What was persisted.
 */

/**
 * @typedef {object} VerifyMagicLinkOptions
 * @property {string | Buffer | Uint8Array} secret
 * @property {MagicLinkStore} store
 * @property {boolean} [consume=true]
 *   When true (default), a successful verify atomically marks the
 *   record consumed so a second click on the same link is rejected as
 *   `reason: 'consumed'`. Turn off if you have a two-phase verify
 *   flow (e.g. preview the destination, then confirm).
 * @property {string} [expectedEmail]
 *   Reject a valid link whose email doesn't match — useful when the
 *   caller already knows which account is pending (e.g. from a
 *   half-authenticated session).
 * @property {string} [prefix]                Must match create-time prefix.
 * @property {number} [now]
 */

/**
 * @typedef {'malformed' | 'bad_signature' | 'expired' | 'not_yet_valid'
 *   | 'not_found' | 'consumed' | 'email_mismatch' | 'email_binding_mismatch'
 *   | 'store_unavailable'} VerifyFailureReason
 */

/**
 * @typedef {{
 *   valid: true,
 *   id: string,
 *   email: string,
 *   redirectTo?: string,
 *   metadata?: Record<string, unknown>,
 * } | { valid: false, reason: VerifyFailureReason }} VerifyMagicLinkResult
 */

/**
 * Mint a single-use magic-link token and its accompanying URL. Send
 * the URL in an email — the package deliberately does not do that
 * itself so you keep control of the mail driver.
 *
 *   const { token, url, id } = await createMagicLink({
 *     secret: process.env.MAGIC_LINK_SECRET,
 *     email: 'user@example.com',
 *     baseUrl: 'https://myapp.com/auth/verify',
 *     expiresIn: '15m',
 *     store,
 *   })
 *   await mailer.send(email, `Sign in: ${url}`)
 *
 * @param {CreateMagicLinkOptions} options
 * @returns {Promise<CreateMagicLinkResult>}
 */
export async function createMagicLink(options) {
  if (!isObject(options)) {
    throw invalidArgument('createMagicLink.options must be an object');
  }
  const secret = _coerceSecret(options.secret, 'createMagicLink.options.secret');
  const email = _requireEmail(options.email, 'createMagicLink.options.email');
  const baseUrl = _requireString(options.baseUrl, 'createMagicLink.options.baseUrl');
  const ttlMs = _requireDuration(options.expiresIn, 'createMagicLink.options.expiresIn');
  _assertStore(options.store, 'createMagicLink.options.store');
  const prefix = isUndefined(options.prefix)
    ? DEFAULT_PREFIX
    : assertPrefix(options.prefix, 'createMagicLink.options.prefix', invalidPrefix);
  _assertStringOrUndef(options.redirectTo, 'createMagicLink.options.redirectTo');
  if (!isUndefined(options.metadata) && !isObject(options.metadata)) {
    throw invalidArgument('createMagicLink.options.metadata must be a plain object when provided');
  }
  const hashEmail = options.hashEmail !== false; // default true

  if (options.maxPerEmail !== undefined) {
    await _applyRateLimit(options.maxPerEmail, email, options.store, 'createMagicLink.options.maxPerEmail');
  }

  const now = _now(options.now);
  const id = newId();
  const payload = {
    id,
    iat: Math.floor(now / 1000),
    exp: Math.floor((now + ttlMs) / 1000),
  };
  if (hashEmail) {
    payload.eh = hashEmailValue(secret, email);
  }

  const token = sign(payload, secret, prefix);
  const url = _appendTokenParam(baseUrl, token);

  /** @type {MagicLinkRecord} */
  const record = {
    id,
    email,
    createdAt: now,
    expiresAt: now + ttlMs,
  };
  if (!isUndefined(options.redirectTo)) {
    record.redirectTo = options.redirectTo;
  }
  if (!isUndefined(options.metadata)) {
    record.metadata = { ...options.metadata };
  }

  try {
    await options.store.put(record);
  } catch (err) {
    throw new MagicLinkError(ErrorCode.STORE_ERROR, `createMagicLink.store.put failed: ${err.message}`, {
      cause: err,
    });
  }
  return { token, url, id, expiresAt: record.expiresAt, record };
}

/**
 * Verify a magic-link token. Returns `{ valid: true, email, ... }` on
 * success, or `{ valid: false, reason }` on any expected failure.
 * Never throws on a bad link — a wrong or stale token is a normal
 * auth outcome.
 *
 * @param {string} token
 * @param {VerifyMagicLinkOptions} options
 * @returns {Promise<VerifyMagicLinkResult>}
 */
export async function verifyMagicLink(token, options) {
  if (!isObject(options)) {
    throw invalidArgument('verifyMagicLink.options must be an object');
  }
  const secret = _coerceSecret(options.secret, 'verifyMagicLink.options.secret');
  _assertStore(options.store, 'verifyMagicLink.options.store');
  const prefix = isUndefined(options.prefix)
    ? DEFAULT_PREFIX
    : assertPrefix(options.prefix, 'verifyMagicLink.options.prefix', invalidPrefix);
  const consume = options.consume !== false; // default true

  const parsed = decode(token, secret, prefix);
  if ('reason' in parsed) {
    return { valid: false, reason: parsed.reason };
  }
  const payload = /** @type {{ id: string, iat: number, exp: number, eh?: string }} */ (parsed.payload);
  const now = _now(options.now);
  const nowSec = Math.floor(now / 1000);
  if (!isNumber(payload.exp) || payload.exp <= nowSec) {
    return { valid: false, reason: 'expired' };
  }
  if (isNumber(payload.iat) && payload.iat > nowSec + 60) {
    return { valid: false, reason: 'not_yet_valid' };
  }
  if (!isString(payload.id) || payload.id.length === 0) {
    return { valid: false, reason: 'malformed' };
  }

  // If `expectedEmail` is supplied and the payload carries `eh`, we can
  // cheaply reject a wrong-email link before ever touching the store.
  if (!isUndefined(options.expectedEmail)) {
    if (!isString(options.expectedEmail)) {
      throw invalidArgument('verifyMagicLink.options.expectedEmail must be a string when provided');
    }
    if (isString(payload.eh)) {
      const expected = hashEmailValue(secret, options.expectedEmail);
      if (expected !== payload.eh) {
        return { valid: false, reason: 'email_mismatch' };
      }
    }
  }

  let record;
  try {
    record = await options.store.getById(payload.id);
  } catch {
    return { valid: false, reason: 'store_unavailable' };
  }
  if (!record) {
    return { valid: false, reason: 'not_found' };
  }
  if (record.consumedAt) {
    return { valid: false, reason: 'consumed' };
  }
  // Cross-check the stored email against the payload's hash — protects
  // against a poisoned store row swapping the email under a valid id.
  if (isString(payload.eh) && hashEmailValue(secret, record.email) !== payload.eh) {
    return { valid: false, reason: 'email_binding_mismatch' };
  }
  if (!isUndefined(options.expectedEmail) && record.email !== options.expectedEmail) {
    return { valid: false, reason: 'email_mismatch' };
  }

  if (consume) {
    let ok;
    try {
      ok = await options.store.consume(payload.id);
    } catch {
      return { valid: false, reason: 'store_unavailable' };
    }
    if (!ok) {
      return { valid: false, reason: 'consumed' };
    }
  }

  /** @type {VerifyMagicLinkResult} */
  const result = { valid: true, id: record.id, email: record.email };
  if (record.redirectTo) {
    result.redirectTo = record.redirectTo;
  }
  if (record.metadata) {
    result.metadata = record.metadata;
  }
  return result;
}

/**
 * List pending (non-consumed, non-expired) magic links for an email.
 * Handy for a "resend last email" flow. Requires the store to
 * implement `listByEmail`.
 *
 * @param {string} email
 * @param {{ store: MagicLinkStore }} options
 * @returns {Promise<MagicLinkRecord[]>}
 */
export async function listPendingForEmail(email, options) {
  if (!isObject(options)) {
    throw invalidArgument('listPendingForEmail.options must be an object');
  }
  _assertStore(options.store, 'listPendingForEmail.options.store');
  _requireEmail(email, 'listPendingForEmail.email');
  if (!isFunction(options.store.listByEmail)) {
    throw invalidArgument('listPendingForEmail requires store.listByEmail — the memory + Redis stores support it');
  }
  const now = Date.now();
  const rows = (await options.store.listByEmail(email)) ?? [];
  return rows.filter(r => !r.consumedAt && r.expiresAt > now);
}

/**
 * Revoke every pending magic link for an email. Useful after a
 * password reset or account termination — invalidates in-flight
 * sign-in emails that haven't been clicked yet.
 *
 * @param {string} email
 * @param {{ store: MagicLinkStore }} options
 * @returns {Promise<number>}    Count of records revoked.
 */
export async function revokeAllForEmail(email, options) {
  if (!isObject(options)) {
    throw invalidArgument('revokeAllForEmail.options must be an object');
  }
  _assertStore(options.store, 'revokeAllForEmail.options.store');
  _requireEmail(email, 'revokeAllForEmail.email');
  if (!isFunction(options.store.revokeByEmail)) {
    throw invalidArgument('revokeAllForEmail requires store.revokeByEmail — the memory + Redis stores support it');
  }
  return options.store.revokeByEmail(email);
}

// ---------------------------------------------------------------------
// internals

function _now(override) {
  return isNumber(override) ? override : Date.now();
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

function _requireEmail(v, name) {
  if (!isString(v) || !EMAIL_RE.test(v)) {
    throw invalidArgument(`${name} must be a well-formed email address`);
  }
  return v;
}

function _requireDuration(input, name) {
  let ms;
  try {
    ms = parseDuration(input);
  } catch (err) {
    throw invalidArgument(`${name}: ${err.message}`, { cause: err });
  }
  if (!isNumber(ms) || ms <= 0) {
    throw invalidArgument(`${name} must resolve to a positive duration; got ${ms}ms`);
  }
  return ms;
}

function _coerceSecret(input, name) {
  if (isString(input)) {
    const buf = Buffer.from(input, 'utf8');
    if (buf.length < MIN_SECRET_BYTES) {
      throw new MagicLinkError(
        ErrorCode.INVALID_SECRET,
        `${name} must be at least ${MIN_SECRET_BYTES} bytes; got ${buf.length}`,
      );
    }
    return buf;
  }
  if (isBytes(input)) {
    if (input.length < MIN_SECRET_BYTES) {
      throw new MagicLinkError(
        ErrorCode.INVALID_SECRET,
        `${name} must be at least ${MIN_SECRET_BYTES} bytes; got ${input.length}`,
      );
    }
    return isBuffer(input) ? input : Buffer.from(input);
  }
  throw invalidArgument(`${name} must be a string, Buffer, or Uint8Array`);
}

function _assertStore(v, name) {
  if (!isObject(v) || !isFunction(v.put) || !isFunction(v.getById) || !isFunction(v.consume)) {
    throw invalidArgument(`${name} must be an object with put / getById / consume methods`);
  }
}

async function _applyRateLimit(config, email, store, name) {
  if (!isObject(config) || !isNumber(config.count) || config.count <= 0) {
    throw invalidArgument(`${name}.count must be a positive number`);
  }
  const windowMs = _requireDuration(config.window, `${name}.window`);
  if (!isFunction(store.incrRate)) {
    throw invalidArgument(
      'createMagicLink.options.store must implement incrRate(email, ttlMs) when maxPerEmail is set',
    );
  }
  const res = await store.incrRate(email, windowMs);
  if (!isObject(res) || !isNumber(res.count)) {
    throw new MagicLinkError(ErrorCode.STORE_ERROR, 'store.incrRate must return { count: number }');
  }
  if (res.count > config.count) {
    throw new MagicLinkError(
      ErrorCode.RATE_LIMITED,
      `magic-link: rate limit exceeded for this email (${res.count} in the last window; cap is ${config.count})`,
      { details: { count: res.count, cap: config.count } },
    );
  }
}

function _appendTokenParam(baseUrl, token) {
  const hashIdx = baseUrl.indexOf('#');
  const base = hashIdx === -1 ? baseUrl : baseUrl.slice(0, hashIdx);
  const sep = base.includes('?') ? '&' : '?';
  return `${base}${sep}token=${encodeURIComponent(token)}`;
}
