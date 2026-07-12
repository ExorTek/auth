import { SecurityError, ErrorCode } from '../internal/errors.js';

/**
 * Freeze the built-in prototypes to defend against prototype pollution.
 * After calling this, code like `req.body.__proto__.isAdmin = true` becomes
 * a no-op (silent in sloppy mode, TypeError in strict). Call once at boot
 * BEFORE loading user code / requiring third-party modules that might set
 * legitimate prototype properties.
 *
 * Idempotent — safe to call multiple times.
 *
 * @param {{ additional?: object[] }} [options]
 *   Extra objects to freeze (e.g. custom global classes).
 * @returns {number}   Count of prototypes frozen.
 */
export function freezePrototypes(options = {}) {
  const defaults = [
    Object.prototype,
    Array.prototype,
    Function.prototype,
    String.prototype,
    Number.prototype,
    Boolean.prototype,
    Map.prototype,
    Set.prototype,
    Promise.prototype,
    Date.prototype,
    RegExp.prototype,
  ];
  const all = [...defaults, ...(options.additional ?? [])];
  let count = 0;
  for (const proto of all) {
    if (proto && !Object.isFrozen(proto)) {
      Object.freeze(proto);
      count += 1;
    }
  }
  return count;
}

/**
 * Race a promise against a timeout. Throws `SecurityError` with
 * `REQUEST_TIMEOUT` when the deadline hits before the promise settles.
 * The underlying promise keeps running — cancellation of Node primitives
 * (setTimeout, fs) needs an AbortController, which this helper doesn't
 * own. Caller passes one in via `options.signal` if it matters.
 *
 * @template T
 * @param {Promise<T>} promise
 * @param {number} ms
 * @param {{ label?: string, signal?: AbortSignal }} [options]
 * @returns {Promise<T>}
 */
export function timeout(promise, ms, options = {}) {
  if (!Number.isFinite(ms) || ms <= 0) {
    throw new SecurityError(ErrorCode.INVALID_ARGUMENT, `timeout: ms must be a positive number; got ${ms}`);
  }
  const label = options.label ?? 'operation';
  return new Promise((resolvePromise, rejectPromise) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) {
        return;
      }
      settled = true;
      rejectPromise(new SecurityError(ErrorCode.REQUEST_TIMEOUT, `${label} timed out after ${ms}ms`));
    }, ms);
    if (typeof timer.unref === 'function') {
      timer.unref();
    }
    if (options.signal) {
      options.signal.addEventListener(
        'abort',
        () => {
          if (settled) {
            return;
          }
          settled = true;
          clearTimeout(timer);
          rejectPromise(new SecurityError(ErrorCode.REQUEST_TIMEOUT, `${label} aborted`));
        },
        { once: true },
      );
    }
    promise.then(
      value => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        resolvePromise(value);
      },
      err => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        rejectPromise(err);
      },
    );
  });
}

/**
 * Body-size guard. Given a claimed content length, returns whether the
 * request may proceed. Middleware should also enforce the limit while
 * reading the body (a lying Content-Length is still an attack surface).
 *
 * @param {number | string | undefined | null} contentLength
 * @param {number} maxBytes
 * @returns {{ ok: boolean, reason?: 'missing' | 'invalid' | 'too-large' }}
 */
export function bodyLimit(contentLength, maxBytes) {
  if (!Number.isInteger(maxBytes) || maxBytes < 0) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `bodyLimit: maxBytes must be a non-negative integer; got ${maxBytes}`,
    );
  }
  if (contentLength === undefined || contentLength === null || contentLength === '') {
    // No Content-Length is ambiguous — chunked transfer, or a genuinely
    // empty body. Callers who need strict enforcement should check
    // separately or gate on Transfer-Encoding.
    return { ok: true, reason: 'missing' };
  }
  const n = typeof contentLength === 'number' ? contentLength : Number(contentLength);
  if (!Number.isFinite(n) || n < 0) {
    return { ok: false, reason: 'invalid' };
  }
  if (n > maxBytes) {
    return { ok: false, reason: 'too-large' };
  }
  return { ok: true };
}

/**
 * @typedef {object} HoneypotOptions
 * @property {string} [fieldName='website']
 *   Common decoys: `website`, `email_address_confirm`, `phone2`.
 * @property {boolean} [caseInsensitive=false]
 */

/**
 * Honeypot check. Modern spam bots blindly fill every form field; a hidden
 * field left empty by the browser is a strong bot signal when it comes
 * back with content. Returns `true` when the request looks like a bot.
 *
 * @param {Record<string, unknown> | undefined | null} body
 * @param {HoneypotOptions} [options]
 * @returns {boolean}
 */
export function honeypot(body, options = {}) {
  if (!body || typeof body !== 'object') {
    return false;
  }
  const fieldName = options.fieldName ?? 'website';
  const value = options.caseInsensitive
    ? (body[fieldName] ?? body[fieldName.toLowerCase()] ?? body[fieldName.toUpperCase()])
    : body[fieldName];
  return typeof value === 'string' && value.length > 0;
}
