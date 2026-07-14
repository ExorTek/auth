import { createSessionManager } from '../manager.js';

/**
 * Fastify plugin factory. Registers preHandler + onSend hooks so that:
 *
 *   1. `request.session` is populated on every request (or `null` if
 *      unauthenticated).
 *   2. `reply.setSession(sessionOrToken)` and `reply.clearSession()`
 *      convenience methods are added to the reply, wiring the
 *      `Set-Cookie` header automatically.
 *   3. `request.sessions` exposes the manager for handlers that need
 *      the full API (rotate, requireFreshAuth, impersonate, …).
 *
 * @param {import('../manager.js').SessionManagerConfig | ReturnType<typeof createSessionManager>} configOrManager
 */
export function sessionPlugin(configOrManager) {
  const sessions =
    typeof configOrManager === 'object' && typeof configOrManager.issue === 'function'
      ? configOrManager
      : createSessionManager(configOrManager);

  const plugin = async function (fastify) {
    fastify.decorateRequest('session', null);
    fastify.decorateRequest('sessions', null);
    fastify.decorateReply('setSessionCookie', null);
    fastify.decorateReply('clearSessionCookie', null);

    fastify.addHook('preHandler', async (request, reply) => {
      request.sessions = sessions;
      request.session = await sessions.verify(request);
      reply.setSessionCookie = value => {
        reply.header('Set-Cookie', appendCookie(reply, value));
      };
      // Returns the promise so callers can `await reply.clearSessionCookie()`
      // before `reply.send()`. Fire-and-forget would race the response
      // and drop the delete-cookie header on the floor.
      reply.clearSessionCookie = async () => {
        const result = await sessions.revoke(request);
        reply.header('Set-Cookie', appendCookie(reply, result.cookie));
        return result;
      };
    });
  };

  plugin[Symbol.for('skip-override')] = true;
  return {
    manager: sessions,
    plugin,
  };
}

/**
 * `reply.header('Set-Cookie', v)` REPLACES the current value — unlike
 * Express's `setHeader` array semantics there is no implicit append. A
 * route that sets a CSRF cookie and then calls `setSessionCookie` would
 * lose the first cookie. Accumulate into an array instead; multiple
 * `Set-Cookie` values on one response are legal.
 */
function appendCookie(reply, value) {
  const existing = typeof reply.getHeader === 'function' ? reply.getHeader('set-cookie') : undefined;
  if (!existing) {
    return value;
  }
  return Array.isArray(existing) ? [...existing, value] : [existing, value];
}

export default sessionPlugin;
