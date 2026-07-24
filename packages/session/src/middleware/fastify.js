import { appendSetCookieHeader } from '@exortek/shared/http';
import { isObject, isFunction } from '@exortek/shared/predicates';
import { fastifyPlugin } from '@exortek/shared/fastify-plugin';

import { createSessionManager } from '../manager.js';

/**
 * Fastify plugin factory. Registers preHandler + onSend hooks so that:
 *
 *   1. `request.session` is populated on every request (or `null` if
 *      unauthenticated).
 *   2. `reply.setSessionCookie(token)` and `reply.clearSessionCookie()`
 *      convenience methods are added to the reply, wiring the
 *      `Set-Cookie` header automatically.
 *   3. `request.sessions` exposes the manager for handlers that need
 *      the full API (rotate, requireFreshAuth, impersonate, …).
 *
 * @param {import('../manager.js').SessionManagerConfig | ReturnType<typeof createSessionManager>} configOrManager
 */
export function sessionPlugin(configOrManager) {
  const sessions =
    isObject(configOrManager) && isFunction(configOrManager.issue)
      ? configOrManager
      : createSessionManager(configOrManager);

  const plugin = fastifyPlugin(
    async function sessionPluginFn(fastify) {
      fastify.decorateRequest('session', null);
      fastify.decorateRequest('sessions', null);
      fastify.decorateReply('setSessionCookie', null);
      fastify.decorateReply('clearSessionCookie', null);

      fastify.addHook('preHandler', async (request, reply) => {
        request.sessions = sessions;
        request.session = await sessions.verify(request);
        // `reply.header('Set-Cookie', v)` REPLACES the current value on
        // Fastify — there's no implicit append. Read whatever the
        // response already has, then let the shared helper stack the new
        // value onto it. Multiple Set-Cookie values on one response are
        // legal.
        reply.setSessionCookie = value => {
          const existing = isFunction(reply.getHeader) ? reply.getHeader('set-cookie') : undefined;
          reply.header('Set-Cookie', appendSetCookieHeader(existing, value));
        };
        // Returns the promise so callers can `await reply.clearSessionCookie()`
        // before `reply.send()`. Fire-and-forget would race the response
        // and drop the delete-cookie header on the floor.
        reply.clearSessionCookie = async () => {
          const result = await sessions.revoke(request);
          const existing = isFunction(reply.getHeader) ? reply.getHeader('set-cookie') : undefined;
          reply.header('Set-Cookie', appendSetCookieHeader(existing, result.cookie));
          return result;
        };
      });
    },
    { name: '@exortek/session' },
  );

  return {
    manager: sessions,
    plugin,
  };
}

export default sessionPlugin;
