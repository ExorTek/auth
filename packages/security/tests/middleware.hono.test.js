import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Hono } from 'hono';
import { rateLimit } from '../src/index.js';
import {
  securityMiddleware,
  corsMiddleware,
  headersMiddleware,
  csrfMiddleware,
  rateLimitMiddleware,
} from '../src/middleware/hono.js';

const SECRET = 'x'.repeat(32);

function makeApp(register) {
  const app = new Hono();
  register(app);
  app.get('/ping', c => c.json({ ok: true }));
  app.post('/echo', async c => {
    let body = null;
    try {
      body = await c.req.json();
    } catch {
      // ignore
    }
    return c.json({ echo: body });
  });
  return app;
}

test('hono: headersMiddleware sets security headers', async () => {
  const app = makeApp(a => a.use('*', headersMiddleware()));
  const res = await app.request('/ping');
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
});

test('hono: corsMiddleware handles preflight + rejects bad origin', async () => {
  const app = makeApp(a => a.use('*', corsMiddleware({ origin: 'https://app.example.com' })));

  const pf = await app.request('/ping', {
    method: 'OPTIONS',
    headers: {
      origin: 'https://app.example.com',
      'access-control-request-method': 'POST',
    },
  });
  assert.equal(pf.status, 204);
  assert.ok(pf.headers.get('access-control-allow-methods'));

  const bad = await app.request('/ping', {
    headers: { origin: 'https://evil.com' },
  });
  assert.equal(bad.status, 403);
});

test('hono: rateLimitMiddleware denies over limit', async () => {
  const store = rateLimit.stores.memory();
  const app = makeApp(a =>
    a.use(
      '*',
      rateLimitMiddleware({
        limiter: rateLimit.fixed({ requests: 2, window: '1m', store }),
        keyGenerator: () => 'k',
      }),
    ),
  );
  await app.request('/ping');
  await app.request('/ping');
  const denied = await app.request('/ping');
  assert.equal(denied.status, 429);
  assert.ok(denied.headers.get('retry-after'));
  store._stop();
});

test('hono: csrfMiddleware issues + verifies', async () => {
  const app = makeApp(a => a.use('*', csrfMiddleware({ secret: SECRET })));

  const g = await app.request('/ping');
  assert.equal(g.status, 200);
  const setCookie = g.headers.get('set-cookie');
  const token = setCookie?.match(/__Host-csrf=([^;]+)/)?.[1];
  assert.ok(token);

  const bad = await app.request('/echo', {
    method: 'POST',
    headers: { cookie: `__Host-csrf=${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  assert.equal(bad.status, 403);

  const ok = await app.request('/echo', {
    method: 'POST',
    headers: {
      cookie: `__Host-csrf=${token}`,
      'x-csrf-token': token,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ x: 1 }),
  });
  assert.equal(ok.status, 200);
});

test('hono: securityMiddleware composes all four', async () => {
  const store = rateLimit.stores.memory();
  const app = makeApp(a =>
    a.use(
      '*',
      securityMiddleware({
        cors: { origin: 'https://app.example.com' },
        csrf: { secret: SECRET },
        rateLimit: {
          limiter: rateLimit.fixed({ requests: 10, window: '1m', store }),
          keyGenerator: () => 'k',
        },
      }),
    ),
  );

  const r = await app.request('/ping', {
    headers: { origin: 'https://app.example.com' },
  });
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(r.headers.get('access-control-allow-origin'), 'https://app.example.com');
  assert.ok(r.headers.get('x-ratelimit-remaining'));
  store._stop();
});
