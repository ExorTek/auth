import { hotp, _verifyHotpForward } from './hotp.js';
import { invalidArgument } from './internal/guards.js';
import { createHash } from 'node:crypto';
import { isString } from '@exortek/shared/predicates';

const DEFAULT_PERIOD = 30;

/**
 * @typedef {import('./hotp.js').OtpAlgorithm} OtpAlgorithm
 */

/**
 * @typedef {object} TotpOptions
 * @property {6 | 7 | 8 | 9 | 10} [digits=6]
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
 *   incr:   (key: string, ttlMs: number) => Promise<{ count: number }>,
 * }} store
 *   Any store shaped like the `@exortek/security` rate-limit stores —
 *   memory / Redis / custom all satisfy this duck type. The guard uses
 *   the store's **atomic** `incr` (Redis `INCR`) as a compare-and-set so
 *   two concurrent requests carrying the same code can't both pass — a
 *   `get`-then-`set` pair would leave a TOCTOU window open.
 * @property {string} key
 *   Caller-provided namespace (typically the user id). We compose the
 *   real store key as `otp:used:<key>:<counter>` — the counter alone
 *   would collide across users.
 */

/**
 * @typedef {object} TotpVerifyOptions
 * @property {6 | 7 | 8 | 9 | 10} [digits=6]
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
    throw invalidArgument(`totp.options.period must be an integer in [1, 3600] seconds; got ${period}`);
  }
}

function counterForTimestamp(timestampMs, period, t0 = 0) {
  return Math.floor((timestampMs / 1000 - t0) / period);
}

function assertT0(t0) {
  if (!Number.isFinite(t0)) {
    throw invalidArgument(`totp.options.t0 must be a finite number of seconds; got ${t0}`);
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
 * @param {number} [t0=0]          Epoch offset in seconds (RFC 6238 "T0").
 *                                 Pass the same value used at enrollment so
 *                                 the countdown lines up with `totp`.
 * @returns {number}               Whole seconds in `(0, period]`.
 */
export function remainingSeconds(period = DEFAULT_PERIOD, timestamp = Date.now(), t0 = 0) {
  assertPeriod(period);
  assertT0(t0);
  const secondsIntoPeriod = Math.floor(timestamp / 1000 - t0) % period;
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
    throw invalidArgument(`verifyTotp.options.window must be an integer in [0, 10]; got ${window}`);
  }

  if (!isString(code) || code.length === 0) {
    return false;
  }

  const center = counterForTimestamp(timestamp, period, t0);
  const start = Math.max(0, center - window);
  const end = center + window;

  // Symmetric skew window mapped onto a forward-only HOTP scan: try every
  // counter in [start, end]. Uses the shared core directly (not verifyHotp)
  // so the span — up to 2×window — isn't rejected by HOTP's [0, 10] guard.
  const matched = _verifyHotpForward(code, secret, start, end - start, digits, algorithm);
  if (matched === null) {
    return false;
  }

  // Replay guard: mark the specific matched counter with a TTL that
  // covers the *remaining* window. A code accepted at T-1 can still be
  // replayed inside T+window until the window rolls off — we block that.
  //
  // Use the store's atomic `incr` as a compare-and-set: the first use
  // creates the key (count === 1) and is allowed; any concurrent or later
  // use sees count > 1 and is rejected. This closes the TOCTOU window a
  // separate get-then-set would leave open under concurrency.
  if (options.replay) {
    const key = replayKey(options.replay.key, secret, matched);
    // TTL: (window + 1) periods forward from now — the code stays inside
    // the acceptance window that long, then naturally rolls off.
    const ttlMs = (window + 1) * period * 1000;
    const { count } = await options.replay.store.incr(key, ttlMs);
    if (count > 1) {
      return false;
    }
  }

  return true;
}

// Namespace the store key by a *hashed* secret so we never write the
// raw secret to a shared store. The counter alone would collide across
// users; the caller's `key` disambiguates them.
function replayKey(callerKey, secret, counter) {
  const digest = createHash('sha256')
    .update(isString(secret) ? secret : Buffer.from(secret))
    .digest('hex')
    .slice(0, 16);
  return `otp:used:${callerKey}:${digest}:${counter}`;
}
