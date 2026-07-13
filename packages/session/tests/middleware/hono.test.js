import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sessionMiddleware } from '../../src/middleware/hono.js';

const SECRET = 'thirty-two-byte-secret-for-session-tests';

// Minimal Hono context mock — c.req.raw is a WHATWG Request; c.set / c.get
// mimic Hono's storage.
function mkCtx(cookie) {
  const bag = new Map();
  const headers = new Headers();
  if (cookie) {
    headers.set('cookie', cookie);
  }
  return {
    req: { raw: new Request('http://x/', { headers }) },
    set: (k, v) => bag.set(k, v),
    get: k => bag.get(k),
    __bag: bag,
  };
}

test('hono: sets session + sessions on the context', async () => {
  const { manager, middleware } = sessionMiddleware({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
  });
  const { token } = await manager.issue({ userId: 'u1' });
  const ctx = mkCtx(`__Host-sid=${encodeURIComponent(token)}`);
  await middleware(ctx, async () => {});
  assert.equal(ctx.get('session')?.userId, 'u1');
  assert.equal(ctx.get('sessions'), manager);
  manager.store._stop();
});

test('hono: session null for missing cookie', async () => {
  const { manager, middleware } = sessionMiddleware({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
  });
  const ctx = mkCtx();
  await middleware(ctx, async () => {});
  assert.equal(ctx.get('session'), null);
  manager.store._stop();
});

test('hono: next is awaited', async () => {
  const { manager, middleware } = sessionMiddleware({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
  });
  const ctx = mkCtx();
  let called = false;
  await middleware(ctx, async () => {
    called = true;
  });
  assert.equal(called, true);
  manager.store._stop();
});
