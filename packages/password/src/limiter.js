import { isObject, isUndefined } from '@exortek/shared/predicates';

import { PasswordError, ErrorCode } from './errors.js';
import { assertFunction, assertPositiveInt, invalidArgument } from './internal/guards.js';

/**
 * @typedef {object} LimiterConfig
 * @property {number} [concurrency=2]
 *   Hashes allowed to run at once. Node runs `scrypt`, `pbkdf2` and
 *   `argon2` on the libuv threadpool — 4 threads by default, shared with
 *   `fs`, `dns.lookup` and `zlib`. Keep this below `UV_THREADPOOL_SIZE` so
 *   a burst of logins cannot take every thread.
 * @property {number} [maxQueue=1000]
 *   Calls allowed to wait for a slot. One past that rejects at once with
 *   `QUEUE_FULL` (HTTP 503) instead of queueing without bound.
 */

/**
 * @template T
 * @typedef {((task: () => Promise<T>) => Promise<T>) & { readonly active: number, readonly pending: number }} Limiter
 */

/**
 * Cap how many password hashes run at once.
 *
 * KDFs are slow on purpose, and Node runs them on the libuv threadpool.
 * When login traffic spikes, unbounded `verify` calls occupy every pool
 * thread and everything else that needs one — file reads, DNS lookups,
 * compression — waits behind them. A limiter keeps the excess in a JS
 * queue instead, leaving threads free, and sheds load once the queue is
 * full.
 *
 * @example
 * const limit = createLimiter({ concurrency: 2 })
 * const ok = await limit(() => password.verify(candidate, user.passwordHash))
 *
 * @param {LimiterConfig} [config]
 * @returns {Limiter<any>}
 */
export function createLimiter(config = {}) {
  if (!isObject(config)) {
    throw invalidArgument('createLimiter.config: expected an object');
  }
  const concurrency = isUndefined(config.concurrency) ? 2 : config.concurrency;
  const maxQueue = isUndefined(config.maxQueue) ? 1000 : config.maxQueue;
  assertPositiveInt(concurrency, 'createLimiter.config.concurrency');
  assertPositiveInt(maxQueue, 'createLimiter.config.maxQueue');

  let active = 0;
  /** @type {Array<() => void>} */
  const queue = [];

  const release = () => {
    active--;
    const next = queue.shift();
    if (next) {
      next();
    }
  };

  /**
   * @template T
   * @param {() => Promise<T>} task
   * @returns {Promise<T>}
   */
  async function limit(task) {
    assertFunction(task, 'limit(task)');
    if (active >= concurrency) {
      if (queue.length >= maxQueue) {
        throw new PasswordError(ErrorCode.QUEUE_FULL, `password limiter queue is full (${maxQueue} waiting)`);
      }
      await new Promise(resolve => queue.push(resolve));
    }
    active++;
    try {
      return await task();
    } finally {
      release();
    }
  }

  Object.defineProperties(limit, {
    active: { get: () => active, enumerable: true },
    pending: { get: () => queue.length, enumerable: true },
  });
  return /** @type {Limiter<any>} */ (limit);
}
