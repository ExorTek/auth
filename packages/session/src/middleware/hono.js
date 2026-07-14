import { createSessionManager } from '../manager.js';

/**
 * Hono middleware factory. Works on Node, Bun, Deno, Cloudflare
 * Workers, and Vercel Edge because `sessions.verify` only touches
 * `node:crypto` (not available on edge runtimes today — see the
 * roadmap). For pure-Node deployments it's fine.
 *
 * Populates the Hono context:
 *   - `c.set('session', ...)`  → `c.get('session')`
 *   - `c.set('sessions', mgr)` → `c.get('sessions')`
 *
 * Session cookie install / clear is done through Hono's stock
 * `c.header('Set-Cookie', ...)` — no wrapper needed.
 *
 * @param {import('../manager.js').SessionManagerConfig | ReturnType<typeof createSessionManager>} configOrManager
 * @returns {{ manager, middleware }}
 */
export function sessionMiddleware(configOrManager) {
  const sessions =
    typeof configOrManager === 'object' && typeof configOrManager.issue === 'function'
      ? configOrManager
      : createSessionManager(configOrManager);

  const middleware = async (c, next) => {
    // Hono's Request is WHATWG-shaped; sessions.verify walks `.headers`
    // via `.get('cookie')`, so hand it the raw Request. Persist per-
    // request cache on the context so a nested call to verify from a
    // route handler still hits the cache.
    const request = { headers: c.req.raw.headers };
    // Surface the client IP so fingerprint binding (`bindTo: ['ip']`)
    // and suspicious-activity detection work. On the Node adapter
    // (@hono/node-server) the raw IncomingMessage rides on `c.env
    // .incoming`; without it (Bun/Deno/Workers) the IP is not
    // derivable here and ip-binding silently degrades to ua-only —
    // pass a manager with `bindTo: ['ua']` on those runtimes.
    const socket = c.env?.incoming?.socket;
    if (socket) {
      request.socket = socket;
    }
    const session = await sessions.verify(request);
    c.set('session', session);
    c.set('sessions', sessions);
    // Expose the same request wrapper so downstream code can call
    // sessions.revoke / rotate with the same headers.
    c.set('__sessionReq', request);
    await next();
  };
  return { manager: sessions, middleware };
}

export default sessionMiddleware;
