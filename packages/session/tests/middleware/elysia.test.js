import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sessionPlugin } from '../../src/middleware/elysia.js';

const SECRET = 'thirty-two-byte-secret-for-session-tests';

// Elysia mock — captures the derive fn so we can exercise it. The real
// Elysia calls derive per-request with a context object; matching that
// shape is enough to validate the plugin.
function mkElysia() {
  const derives = [];
  return {
    derive(fn) {
      derives.push(fn);
      return this;
    },
    __run: async ctx => {
      const results = [];
      for (const fn of derives) {
        results.push(await fn(ctx));
      }
      return Object.assign({}, ...results);
    },
  };
}

test('elysia plugin: derive populates session + sessions', async () => {
  const { manager, plugin } = sessionPlugin({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  const { token } = await manager.issue({ userId: 'u1' });
  const elysia = mkElysia();
  await plugin(elysia);
  const headers = new Headers({ cookie: `__Host-sid=${encodeURIComponent(token)}` });
  const derived = await elysia.__run({ request: { headers } });
  assert.equal(derived.session?.userId, 'u1');
  assert.equal(derived.sessions, manager);
  manager.store._stop();
});

test('elysia plugin: session null when no cookie', async () => {
  const { manager, plugin } = sessionPlugin({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  const elysia = mkElysia();
  await plugin(elysia);
  const derived = await elysia.__run({ request: { headers: new Headers() } });
  assert.equal(derived.session, null);
  manager.store._stop();
});
