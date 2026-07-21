/**
 * Duck-type guard for a Redis-compatible client. Every `@exortek/*`
 * package that ships a Redis store (jwt blacklist, session store,
 * security rate-limit) does the same "not null + required methods
 * are functions" check up front so a missing dependency surfaces as
 * a clean typed error instead of `TypeError: client.get is not a
 * function` deep in a store operation.
 *
 * Callers pass their own `wrap` callback that throws their typed
 * error class with the message — this file has no opinion on the
 * error surface.
 */

/**
 * @param {unknown} client
 * @param {readonly string[]} methods  Method names that must be functions on the client.
 * @param {(message: string) => never} wrap
 *   Called with a diagnostic message when the check fails; must throw.
 *   The caller's typed error class is emitted from inside this callback.
 * @returns {void}
 */
export function assertRedisClient(client, methods, wrap) {
  if (!client || typeof client !== 'object') {
    wrap('client is required — pass a Redis-compatible instance (ioredis / node-redis / @upstash/redis)');
  }
  const c = /** @type {Record<string, unknown>} */ (client);
  for (const method of methods) {
    if (typeof c[method] !== 'function') {
      wrap(`client is missing '${method}()' — is this a Redis-compatible client?`);
    }
  }
}
