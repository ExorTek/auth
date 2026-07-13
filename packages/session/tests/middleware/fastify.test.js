import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sessionPlugin } from '../../src/middleware/fastify.js';

const SECRET = 'thirty-two-byte-secret-for-session-tests';

// Minimal Fastify mock — captures the hooks the plugin registers so we
// can invoke them manually. Not a full fastify runtime; validates the
// plugin's contract with fastify's plugin surface.
function mkFastify() {
  const decoratedRequest = {};
  const decoratedReply = {};
  const hooks = { preHandler: [] };
  return {
    decorateRequest(name, val) {
      decoratedRequest[name] = val;
    },
    decorateReply(name, val) {
      decoratedReply[name] = val;
    },
    addHook(name, fn) {
      hooks[name] = hooks[name] ?? [];
      hooks[name].push(fn);
    },
    __invoke: async (req, reply) => {
      for (const fn of hooks.preHandler) {
        await fn(req, reply);
      }
    },
  };
}

test('fastify plugin: decorates request + reply and populates session', async () => {
  const { manager, plugin } = sessionPlugin({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
  });
  const { token } = await manager.issue({ userId: 'u1' });
  const fastify = mkFastify();
  await plugin(fastify);

  const request = { headers: { cookie: `__Host-sid=${encodeURIComponent(token)}` } };
  const replyHeaders = {};
  const reply = {
    header(name, value) {
      replyHeaders[name] = value;
    },
  };
  await fastify.__invoke(request, reply);
  assert.equal(request.session?.userId, 'u1');
  assert.equal(request.sessions, manager);
  assert.equal(typeof reply.setSessionCookie, 'function');

  reply.setSessionCookie('__Host-sid=fresh; Path=/; Secure');
  assert.equal(replyHeaders['Set-Cookie'], '__Host-sid=fresh; Path=/; Secure');
  manager.store._stop();
});

test('fastify plugin: skip-override symbol set', async () => {
  const { plugin, manager } = sessionPlugin({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  assert.equal(plugin[Symbol.for('skip-override')], true);
  manager.store._stop();
});
