import { createHash } from 'node:crypto';
import { PasswordError, ErrorCode } from './errors.js';

const DEFAULT_ENDPOINT = 'https://api.pwnedpasswords.com/range/';
const DEFAULT_TIMEOUT_MS = 5000;

/**
 * @typedef {object} HibpOptions
 * @property {string} [endpoint='https://api.pwnedpasswords.com/range/']
 *   Override for HIBP mirrors or self-hosted proxies. Trailing slash required.
 * @property {number} [timeoutMs=5000]
 *   Network timeout. Longer than 5s ties up the signup path — better
 *   to fail-open (see {@link HibpCheckOptions.failOpen}) than block on
 *   a slow HIBP mirror.
 * @property {string} [userAgent]
 *   HIBP's TOS requires a descriptive User-Agent. Defaults to
 *   `@exortek/password/<version>` — override with your app name in
 *   production so HIBP can reach you if there's an abuse issue.
 * @property {typeof fetch} [fetch]
 *   Injectable fetch implementation. Node 22+ ships a global `fetch`;
 *   pass a mock here for tests.
 */

/**
 * @typedef {object} HibpCheckOptions
 * @property {boolean} [failOpen=false]
 *   When `true`, a network / HTTP error resolves to `{ pwned: false, count: 0 }`
 *   rather than raising `HIBP_UNAVAILABLE`. Use this for signup flows
 *   where availability is more important than perfect blocking. Never
 *   fail-open on password *reset* — those flows should hard-fail rather
 *   than silently accept a possibly-breached password.
 */

/**
 * @typedef {object} HibpCheckResult
 * @property {boolean} pwned    True when HIBP has ≥ 1 breach record.
 * @property {number} count     Occurrence count in HIBP's dataset. Higher
 *                              = more widely reused / more dangerous.
 */

/**
 * Query the Have I Been Pwned "Pwned Passwords" API using the
 * k-anonymity endpoint. Only the first 5 characters of the SHA-1 hash
 * ever leave your process — HIBP returns all hashes with that prefix
 * and this function checks the remaining bytes locally.
 *
 * See https://haveibeenpwned.com/API/v3#PwnedPasswords for the API
 * contract and https://haveibeenpwned.com/API/AbuseGuidelines for
 * User-Agent / rate-limit expectations.
 *
 * @example
 * const hibp = createHibpClient({ userAgent: 'my-app/1.0' })
 * const check = await hibp.check(candidate, { failOpen: true })
 * if (check.pwned) {
 *   return badRequest(`this password appears in ${check.count} known breaches`)
 * }
 *
 * @param {HibpOptions} [options]
 */
export function createHibpClient(options = {}) {
  const endpoint = options.endpoint ?? DEFAULT_ENDPOINT;
  if (typeof endpoint !== 'string' || !endpoint.endsWith('/')) {
    throw new PasswordError(
      ErrorCode.INVALID_ARGUMENT,
      `createHibpClient: endpoint must end with '/'; got '${endpoint}'`,
    );
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60_000) {
    throw new PasswordError(
      ErrorCode.INVALID_ARGUMENT,
      `createHibpClient: timeoutMs must be an integer in [100, 60000]; got ${timeoutMs}`,
    );
  }
  const userAgent = options.userAgent ?? '@exortek/password';
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    throw new PasswordError(
      ErrorCode.INVALID_ARGUMENT,
      "createHibpClient: no global fetch available and none was injected. Node 22+ ships a global fetch; on older runtimes pass `fetch: (await import('undici')).fetch`.",
    );
  }

  return {
    /**
     * Check whether a password appears in HIBP. See {@link HibpCheckResult}.
     * @param {string} password
     * @param {HibpCheckOptions} [checkOptions]
     * @returns {Promise<HibpCheckResult>}
     */
    async check(password, checkOptions = {}) {
      if (typeof password !== 'string' || password.length === 0) {
        throw new PasswordError(ErrorCode.INVALID_ARGUMENT, 'hibp.check: password is required');
      }
      const sha1 = createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
      const prefix = sha1.slice(0, 5);
      const suffix = sha1.slice(5);
      const url = `${endpoint}${prefix}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      let body;
      try {
        const response = await fetchImpl(url, {
          method: 'GET',
          headers: {
            'user-agent': userAgent,
            'add-padding': 'true',
          },
          signal: controller.signal,
        });
        if (!response.ok) {
          throw new Error(`HIBP responded with ${response.status}`);
        }
        body = await response.text();
      } catch (cause) {
        if (checkOptions.failOpen) {
          return { pwned: false, count: 0 };
        }
        throw new PasswordError(
          ErrorCode.HIBP_UNAVAILABLE,
          `hibp.check: request failed — ${cause instanceof Error ? cause.message : String(cause)}`,
          { cause },
        );
      } finally {
        clearTimeout(timer);
      }
      // The response is text/plain with lines like `SUFFIX:count`. With
      // `add-padding: true` HIBP interleaves fake entries — those have
      // count = 0 and are safe to walk past.
      for (const line of body.split(/\r?\n/)) {
        const colon = line.indexOf(':');
        if (colon === -1) {
          continue;
        }
        const lineSuffix = line.slice(0, colon).trim().toUpperCase();
        if (lineSuffix === suffix) {
          const count = Number.parseInt(line.slice(colon + 1).trim(), 10);
          if (count > 0) {
            return { pwned: true, count };
          }
        }
      }
      return { pwned: false, count: 0 };
    },
  };
}
