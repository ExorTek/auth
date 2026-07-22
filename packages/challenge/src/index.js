/**
 * `@exortek/challenge` — signed, single-use challenge tokens for
 * multi-step auth flows.
 *
 * A challenge is a small, HMAC-signed envelope that carries context
 * across a redirect or a follow-up request without a server-side
 * session: who is being challenged (`userId`), how they proved
 * themselves so far (`method`), what step of the flow they've cleared
 * (`step`), and any bespoke metadata the caller needs on the other
 * side. The token is stateless by default; single-use enforcement and
 * revocation are opt-in via a store the caller supplies.
 *
 * See the README for the full API and worked examples.
 */

import { parseDuration } from '@exortek/shared/duration';
import {
  isBytes,
  isBuffer,
  isFiniteNumber,
  isFunction,
  isNumber,
  isObject,
  isString,
  isUndefined,
} from '@exortek/shared/predicates';

import { ChallengeError, ErrorCode } from './errors.js';
import { invalidArgument } from './internal/guards.js';
import { DEFAULT_PREFIX, assertPrefix, decode, newJti, sign } from './token.js';

export { ChallengeError, ErrorCode } from './errors.js';

const MIN_SECRET_BYTES = 32;

const KNOWN_METHODS = new Set([
  'totp',
  'hotp',
  'email_otp',
  'sms_otp',
  'backup_code',
  'passkey',
  'magic_link',
  'password',
  'webauthn',
  'oauth',
  'oidc',
]);

/**
 * @typedef {'totp' | 'hotp' | 'email_otp' | 'sms_otp' | 'backup_code'
 *   | 'passkey' | 'magic_link' | 'password' | 'webauthn' | 'oauth' | 'oidc'
 *   | string} ChallengeMethod
 */

/**
 * @typedef {object} IncrStore
 * @property {(key: string, ttlMs: number) => Promise<{ count: number }>} incr
 *   Atomic increment-with-expiry. First call returns `{ count: 1 }` and
 *   arms a TTL; subsequent calls before expiry return the incremented
 *   count. Used as compare-and-set for single-use enforcement.
 */

/**
 * @typedef {object} ChallengePayload
 * @property {string} jti
 * @property {number} iat
 * @property {number} exp
 * @property {string} [userId]
 * @property {ChallengeMethod} [method]
 * @property {string} [step]
 * @property {string} [nextStep]
 * @property {string} [ip]                      Only set when `ipBinding: true`.
 * @property {string} [ua]                      Only set when `ua` supplied.
 * @property {Record<string, unknown>} [meta]
 */

/**
 * @typedef {object} CreateChallengeOptions
 * @property {string | Buffer | Uint8Array} secret
 *   HMAC-SHA256 secret. **Must be at least 32 raw bytes.** A string is
 *   interpreted as UTF-8 — for a hex or base64 secret, decode to
 *   Buffer first.
 * @property {string} [userId]
 * @property {ChallengeMethod} [method]
 * @property {string} [step]
 * @property {string} [nextStep]
 * @property {string} [ip]
 * @property {string} [ua]
 * @property {Record<string, unknown>} [metadata]
 * @property {string | number} expiresIn        Duration string (`'5m'`) or ms integer.
 * @property {boolean} [singleUse=false]
 *   When true, the returned token can only be verified once — subsequent
 *   verifies with `consume: true` fail with `reason: 'replay'`. Requires
 *   `store` to be supplied.
 * @property {IncrStore} [store]
 *   Any object exposing `incr(key, ttlMs) → { count }`. Compatible with
 *   `@exortek/security`'s rate-limit stores; also easy to wrap Redis.
 * @property {boolean} [ipBinding=false]
 *   When true, the caller-supplied `ip` is stamped into the payload and
 *   `verifyChallenge` will reject a request whose `ip` differs.
 * @property {string} [prefix='chall_v1']
 *   Wire-format prefix. Defaults to `'chall_v1'` — the value shipped
 *   with this package. Callers can override to brand the token
 *   family (e.g. `'server_challenge'`, `'myapp_v1'`); must match
 *   `/^[A-Za-z0-9_-]{1,32}$/`. The same prefix must be passed at
 *   verify time or verification returns `reason: 'malformed'`.
 * @property {number} [now]                     Override `Date.now()` for testing.
 */

/**
 * @typedef {object} VerifyChallengeOptions
 * @property {string | Buffer | Uint8Array} secret
 * @property {boolean} [consume=false]
 *   Enforce single-use. Requires `store` (typically the same one used
 *   at create time).
 * @property {IncrStore} [store]
 * @property {string} [expectedUserId]
 * @property {ChallengeMethod} [expectedMethod]
 * @property {string} [expectedStep]
 * @property {string} [expectedNextStep]
 * @property {string} [ip]
 *   The current request's IP. Required to verify a token that was
 *   created with `ipBinding: true`; ignored otherwise.
 * @property {string} [prefix='chall_v1']
 *   Wire-format prefix. Must match the value passed to
 *   `createChallenge` — a token minted with a different prefix will
 *   fail with `reason: 'malformed'`.
 * @property {number} [now]                     Override `Date.now()` for testing.
 */

/**
 * @typedef {'malformed' | 'bad_signature' | 'expired' | 'not_yet_valid'
 *   | 'user_mismatch' | 'method_mismatch' | 'step_mismatch'
 *   | 'next_step_mismatch' | 'ip_mismatch' | 'ip_missing' | 'replay'
 *   | 'store_unavailable'} VerifyFailureReason
 */

/**
 * @typedef {{ valid: true, payload: ChallengePayload }
 *   | { valid: false, reason: VerifyFailureReason }} VerifyChallengeResult
 */

/**
 * Create a signed challenge token.
 *
 *   const token = await createChallenge({
 *     secret: process.env.CHALLENGE_SECRET,
 *     userId: 'usr_123',
 *     method: 'totp',
 *     step: 'mfa_verified',
 *     nextStep: 'login',
 *     expiresIn: '5m',
 *     singleUse: true,
 *     store,
 *   })
 *
 * @param {CreateChallengeOptions} options
 * @returns {Promise<string>}
 */
export async function createChallenge(options) {
  if (!isObject(options)) {
    throw invalidArgument('createChallenge.options must be an object');
  }
  const secret = _coerceSecret(options.secret, 'createChallenge.options.secret');
  let ttlMs;
  try {
    ttlMs = parseDuration(options.expiresIn);
  } catch (err) {
    throw invalidArgument(`createChallenge.options.expiresIn: ${err.message}`, { cause: err });
  }
  if (!isFiniteNumber(ttlMs) || ttlMs <= 0) {
    throw invalidArgument(`createChallenge.options.expiresIn must resolve to a positive duration; got ${ttlMs}ms`);
  }
  const prefix = isUndefined(options.prefix)
    ? DEFAULT_PREFIX
    : assertPrefix(options.prefix, 'createChallenge.options.prefix', invalidArgument);
  _assertStringOrUndef(options.userId, 'createChallenge.options.userId');
  _assertMethod(options.method, 'createChallenge.options.method');
  _assertStringOrUndef(options.step, 'createChallenge.options.step');
  _assertStringOrUndef(options.nextStep, 'createChallenge.options.nextStep');
  _assertStringOrUndef(options.ua, 'createChallenge.options.ua');

  const singleUse = options.singleUse === true;
  const ipBinding = options.ipBinding === true;

  if (singleUse && !_isStore(options.store)) {
    throw invalidArgument(
      'createChallenge.options.store is required when singleUse: true — pass an object exposing incr(key, ttlMs) → { count }',
    );
  }
  if (ipBinding && !isString(options.ip)) {
    throw invalidArgument('createChallenge.options.ip must be a string when ipBinding: true');
  }
  if (!isUndefined(options.metadata) && !isObject(options.metadata)) {
    throw invalidArgument('createChallenge.options.metadata must be a plain object when provided');
  }

  const now = _now(options.now);
  const jti = newJti();

  /** @type {ChallengePayload} */
  const payload = {
    jti,
    iat: Math.floor(now / 1000),
    exp: Math.floor((now + ttlMs) / 1000),
  };
  if (options.userId) {
    payload.userId = options.userId;
  }
  if (options.method) {
    payload.method = options.method;
  }
  if (options.step) {
    payload.step = options.step;
  }
  if (options.nextStep) {
    payload.nextStep = options.nextStep;
  }
  if (ipBinding) {
    payload.ip = options.ip;
  }
  if (isString(options.ua)) {
    payload.ua = options.ua;
  }
  if (!isUndefined(options.metadata)) {
    payload.meta = options.metadata;
  }
  if (singleUse) {
    payload.su = 1;
  }

  return sign(payload, secret, prefix);
}

/**
 * Verify a challenge token. Returns `{ valid: true, payload }` on
 * success or `{ valid: false, reason }` on any expected failure. Only
 * throws on programmer errors (bad options, missing secret).
 *
 *   const res = await verifyChallenge(token, {
 *     secret: process.env.CHALLENGE_SECRET,
 *     consume: true,
 *     store,
 *     expectedUserId: pendingUserId,
 *     expectedMethod: 'totp',
 *     ip: req.ip,
 *   })
 *   if (!res.valid) return reply.code(401).send({ error: res.reason })
 *
 * @param {string} token
 * @param {VerifyChallengeOptions} options
 * @returns {Promise<VerifyChallengeResult>}
 */
export async function verifyChallenge(token, options) {
  if (!isObject(options)) {
    throw invalidArgument('verifyChallenge.options must be an object');
  }
  const secret = _coerceSecret(options.secret, 'verifyChallenge.options.secret');
  const consume = options.consume === true;
  if (consume && !_isStore(options.store)) {
    throw invalidArgument(
      'verifyChallenge.options.store is required when consume: true — pass the same store used at create time',
    );
  }
  const prefix = isUndefined(options.prefix)
    ? DEFAULT_PREFIX
    : assertPrefix(options.prefix, 'verifyChallenge.options.prefix', invalidArgument);

  const parsed = decode(token, secret, prefix);
  if ('reason' in parsed) {
    return { valid: false, reason: parsed.reason };
  }
  const payload = /** @type {ChallengePayload & { su?: 1 }} */ (parsed.payload);
  const now = _now(options.now);
  const nowSec = Math.floor(now / 1000);

  if (!isNumber(payload.exp) || payload.exp <= nowSec) {
    return { valid: false, reason: 'expired' };
  }
  if (isNumber(payload.iat) && payload.iat > nowSec + 60) {
    // Small clock-skew tolerance (60s) — reject only if clearly future-dated.
    return { valid: false, reason: 'not_yet_valid' };
  }
  if (!isUndefined(options.expectedUserId) && payload.userId !== options.expectedUserId) {
    return { valid: false, reason: 'user_mismatch' };
  }
  if (!isUndefined(options.expectedMethod) && payload.method !== options.expectedMethod) {
    return { valid: false, reason: 'method_mismatch' };
  }
  if (!isUndefined(options.expectedStep) && payload.step !== options.expectedStep) {
    return { valid: false, reason: 'step_mismatch' };
  }
  if (!isUndefined(options.expectedNextStep) && payload.nextStep !== options.expectedNextStep) {
    return { valid: false, reason: 'next_step_mismatch' };
  }
  if (!isUndefined(payload.ip)) {
    if (!isString(options.ip)) {
      return { valid: false, reason: 'ip_missing' };
    }
    if (options.ip !== payload.ip) {
      return { valid: false, reason: 'ip_mismatch' };
    }
  }
  if (consume && payload.su === 1) {
    const ttlMs = Math.max(1, payload.exp * 1000 - now);
    let count;
    try {
      // Namespace lives in the store's own keyPrefix (redisStore defaults
      // to 'chall:'). verifyChallenge passes the raw jti so a store shared
      // with other purposes can prefix once — no double 'chall:chall:'.
      const res = await options.store.incr(payload.jti, ttlMs);
      count = res?.count;
    } catch {
      return { valid: false, reason: 'store_unavailable' };
    }
    if (!isNumber(count) || count > 1) {
      return { valid: false, reason: 'replay' };
    }
  }
  // Strip internal fields so callers see only their own payload.
  const { su: _su, ...clean } = payload;
  return { valid: true, payload: clean };
}

function _coerceSecret(input, name) {
  if (isString(input)) {
    const buf = Buffer.from(input, 'utf8');
    if (buf.length < MIN_SECRET_BYTES) {
      throw new ChallengeError(
        ErrorCode.INVALID_SECRET,
        `${name} must be at least ${MIN_SECRET_BYTES} bytes; got ${buf.length}. Generate one with: node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"`,
      );
    }
    return buf;
  }
  if (isBytes(input)) {
    if (input.length < MIN_SECRET_BYTES) {
      throw new ChallengeError(
        ErrorCode.INVALID_SECRET,
        `${name} must be at least ${MIN_SECRET_BYTES} bytes; got ${input.length}`,
      );
    }
    return isBuffer(input) ? input : Buffer.from(input);
  }
  throw invalidArgument(`${name} must be a string, Buffer, or Uint8Array`);
}

function _assertStringOrUndef(v, name) {
  if (!isUndefined(v) && !isString(v)) {
    throw invalidArgument(`${name} must be a string when provided`);
  }
}

function _assertMethod(v, name) {
  if (isUndefined(v)) {
    return;
  }
  if (!isString(v)) {
    throw invalidArgument(`${name} must be a string when provided`);
  }
  if (!KNOWN_METHODS.has(v)) {
    // Not fatal — some callers have custom methods. Just note it.
    // (We keep the check off to preserve extensibility; the list is
    // documented as guidance, not policy.)
  }
}

function _isStore(v) {
  return isObject(v) && isFunction(v.incr);
}

function _now(override) {
  return isNumber(override) ? override : Date.now();
}
