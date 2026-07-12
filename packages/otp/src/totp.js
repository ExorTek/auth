import { hotp, verifyHotp } from './hotp.js';
import { OtpError, ErrorCode } from './internal/errors.js';
import { createHash } from 'node:crypto';

const DEFAULT_PERIOD = 30;

/**
 * @typedef {import('./hotp.js').OtpAlgorithm} OtpAlgorithm
 */

/**
 * @typedef {object} TotpOptions
 * @property {6 | 7 | 8} [digits=6]
 * @property {OtpAlgorithm} [algorithm='SHA1']
 * @property {number} [period=30]        Seconds per code. RFC 6238 default is 30.
 * @property {number} [timestamp]        Override "now" in ms since epoch.
 *                                       Useful for testing; production
 *                                       code should leave it undefined.
 * @property {number} [t0=0]             Epoch offset in seconds — RFC 6238
 *                                       calls this "T0". Almost every
 *                                       deployment leaves it at 0 (Unix
 *                                       epoch); a handful of legacy SecurID
 *                                       migrations use a custom start.
 */

/**
 * @typedef {object} ReplayGuard
 * @property {{
 *   get:    (key: string) => Promise<unknown>,
 *   set:    (key: string, value: unknown, ttlMs: number) => Promise<void>,
 * }} store
 *   Any store shaped like the `@exortek/security` rate-limit stores —
 *   memory / Redis / custom all satisfy this duck type. Only `get` and
 *   `set` are used; no `incr` needed.
 * @property {string} key
 *   Caller-provided namespace (typically the user id). We compose the
 *   real store key as `otp:used:<key>:<counter>` — the counter alone
 *   would collide across users.
 */

/**
 * @typedef {object} TotpVerifyOptions
 * @property {6 | 7 | 8} [digits=6]
 * @property {OtpAlgorithm} [algorithm='SHA1']
 * @property {number} [period=30]
 * @property {number} [window=1]
 *   Skew tolerance in periods. `window: 1` accepts `T-1`, `T`, and
 *   `T+1` — the same tolerance Google Authenticator applies internally.
 *   `window: 0` is strict; `window: 2+` gets progressively less
 *   defensive against brute-force.
 * @property {number} [timestamp]        Override "now" (ms since epoch).
 * @property {number} [t0=0]             Epoch offset in seconds. Match the value
 *                                       used at enrollment.
 * @property {ReplayGuard} [replay]
 *   Opt-in replay defence: after a successful verify we mark that
 *   specific counter as "used" for the remaining validity of the
 *   window, so a stolen code can't be reused inside its slop period.
 *   Requires an async store.
 */

function assertPeriod(period) {
  if (!Number.isInteger(period) || period < 1 || period > 3600) {
    throw new OtpError(
      ErrorCode.INVALID_ARGUMENT,
      `TOTP period must be an integer in [1, 3600] seconds; got ${period}`,
    );
  }
}

function counterForTimestamp(timestampMs, period, t0 = 0) {
  return Math.floor((timestampMs / 1000 - t0) / period);
}

function assertT0(t0) {
  if (!Number.isFinite(t0)) {
    throw new OtpError(ErrorCode.INVALID_ARGUMENT, `TOTP t0 must be a finite number of seconds; got ${t0}`);
  }
}

/**
 * Current TOTP for the given secret.
 *
 * @param {string | Buffer | Uint8Array} secret
 * @param {TotpOptions} [options]
 * @returns {string}
 */
export function totp(secret, options = {}) {
  const period = options.period ?? DEFAULT_PERIOD;
  const timestamp = options.timestamp ?? Date.now();
  const t0 = options.t0 ?? 0;
  assertPeriod(period);
  assertT0(t0);
  const counter = counterForTimestamp(timestamp, period, t0);
  return hotp(secret, counter, {
    digits: options.digits,
    algorithm: options.algorithm,
  });
}

/**
 * Seconds remaining before the current TOTP code rolls over. Handy for
 * the countdown ring most 2FA screens show.
 *
 * @param {number} [period=30]
 * @param {number} [timestamp]     ms since epoch, default Date.now().
 * @returns {number}               Whole seconds in `[0, period)`.
 */
export function remainingSeconds(period = DEFAULT_PERIOD, timestamp = Date.now()) {
  assertPeriod(period);
  const secondsIntoPeriod = Math.floor(timestamp / 1000) % period;
  return period - secondsIntoPeriod;
}

/**
 * Verify a TOTP code with configurable drift tolerance.
 *
 * Returns `true` on success (with optional silent replay guard) or
 * `false` on any failure. Never throws for user-input problems —
 * a wrong code is a normal auth-outcome, not an error.
 *
 * @param {unknown} code
 * @param {string | Buffer | Uint8Array} secret
 * @param {TotpVerifyOptions} [options]
 * @returns {Promise<boolean>}
 */
export async function verifyTotp(code, secret, options = {}) {
  const period = options.period ?? DEFAULT_PERIOD;
  const window = options.window ?? 1;
  const digits = options.digits ?? 6;
  const algorithm = options.algorithm ?? 'SHA1';
  const timestamp = options.timestamp ?? Date.now();
  const t0 = options.t0 ?? 0;
  assertPeriod(period);
  assertT0(t0);
  if (!Number.isInteger(window) || window < 0 || window > 10) {
    throw new OtpError(ErrorCode.INVALID_ARGUMENT, `TOTP window must be an integer in [0, 10]; got ${window}`);
  }

  if (typeof code !== 'string' || code.length === 0) {
    return false;
  }

  const center = counterForTimestamp(timestamp, period, t0);
  const start = center - window;
  const end = center + window;

  // Reuse verifyHotp's loop, but symmetric around the current counter.
  // We pass `window * 2` as its forward-only window and start at the
  // earliest candidate.
  const matched = verifyHotp(code, secret, Math.max(0, start), {
    digits,
    algorithm,
    window: end - Math.max(0, start),
  });
  if (matched === null) {
    return false;
  }

  // Replay guard: record the specific matched counter with a TTL that
  // covers the *remaining* window. A code accepted at T-1 can still be
  // replayed inside T+window until the window rolls off — we block that.
  if (options.replay) {
    const key = replayKey(options.replay.key, secret, matched);
    const existing = await options.replay.store.get(key);
    if (existing) {
      return false;
    }
    // TTL: (window + 1) periods forward from now — the code stays inside
    // the acceptance window that long, then naturally rolls off.
    const ttlMs = (window + 1) * period * 1000;
    await options.replay.store.set(key, 1, ttlMs);
  }

  return true;
}

// Namespace the store key by a *hashed* secret so we never write the
// raw secret to a shared store. The counter alone would collide across
// users; the caller's `key` disambiguates them.
function replayKey(callerKey, secret, counter) {
  const digest = createHash('sha256')
    .update(typeof secret === 'string' ? secret : Buffer.from(secret))
    .digest('hex')
    .slice(0, 16);
  return `otp:used:${callerKey}:${digest}:${counter}`;
}
