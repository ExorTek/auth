import { createSessionManager } from '../manager.js';

/**
 * Elysia plugin factory. Uses `derive` to inject the current session +
 * manager onto the request context. Matches the shape `@elysiajs/*`
 * community plugins use for auth.
 *
 * Usage:
 *
 *   const app = new Elysia()
 *     .use(sessionPlugin({ secret, ttl: '7d', idleTtl: '30m' }))
 *     .get('/me', ({ session }) => session ?? { user: null })
 *
 * `set.headers['Set-Cookie']` is where you write the sealed cookie back —
 * consistent with how `@elysiajs/cors` and `@elysiajs/csrf` install
 * their headers.
 *
 * @param {import('../manager.js').SessionManagerConfig | ReturnType<typeof createSessionManager>} configOrManager
 */
export function sessionPlugin(configOrManager) {
  const sessions =
    typeof configOrManager === 'object' && typeof configOrManager.issue === 'function'
      ? configOrManager
      : createSessionManager(configOrManager);

  // Return a factory function — Elysia consumers pass this into
  // `app.use(sessionPlugin(config))`. We can't hard-import 'elysia'
  // here (that would break tree-shakability), so the returned object
  // is a plain hook descriptor Elysia's `.use` accepts.
  const plugin = async elysiaApp => {
    return elysiaApp.derive(async context => {
      const request = { headers: context.request.headers };
      const session = await sessions.verify(request);
      return {
        session,
        sessions,
        __sessionReq: request,
      };
    });
  };

  return {
    manager: sessions,
    plugin,
  };
}

export default sessionPlugin;
