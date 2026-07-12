import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Elysia } from 'elysia';
import { rateLimit } from '../src/index.js';
import {
  securityMiddleware,
  corsMiddleware,
  headersMiddleware,
  csrfMiddleware,
  rateLimitMiddleware,
} from '../src/middleware/elysia.js';

const SECRET = 'x'.repeat(32);

// Chained pattern: Elysia's `.use()` with a named sub-instance plugin
// composes but doesn't mutate — the return value is the composed app.
function makeApp(register) {
  return register(new Elysia())
    .get('/ping', () => ({ ok: true }))
    .post('/echo', ({ body }) => ({ echo: body ?? null }));
}

test('elysia: headersMiddleware sets security headers', async () => {
  const app = makeApp(a => a.use(headersMiddleware()));
  const res = await app.handle(new Request('http://localhost/ping'));
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
});

test('elysia: corsMiddleware handles preflight', async () => {
  const app = makeApp(a => a.use(corsMiddleware({ origin: 'https://app.example.com' })));
  const pf = await app.handle(
    new Request('http://localhost/ping', {
      method: 'OPTIONS',
      headers: {
        origin: 'https://app.example.com',
        'access-control-request-method': 'POST',
      },
    }),
  );
  assert.equal(pf.status, 204);
});

test('elysia: corsMiddleware rejects bad origin', async () => {
  const app = makeApp(a => a.use(corsMiddleware({ origin: 'https://app.example.com' })));
  const res = await app.handle(
    new Request('http://localhost/ping', {
      headers: { origin: 'https://evil.com' },
    }),
  );
  assert.equal(res.status, 403);
});

test('elysia: rateLimitMiddleware denies over limit', async () => {
  const store = rateLimit.stores.memory();
  const app = makeApp(a =>
    a.use(
      rateLimitMiddleware({
        limiter: rateLimit.fixed({ requests: 2, window: '1m', store }),
        keyGenerator: () => 'k',
      }),
    ),
  );
  await app.handle(new Request('http://localhost/ping'));
  await app.handle(new Request('http://localhost/ping'));
  const denied = await app.handle(new Request('http://localhost/ping'));
  assert.equal(denied.status, 429);
  assert.ok(denied.headers.get('retry-after'));
  store._stop();
});

test('elysia: csrfMiddleware issues + verifies', async () => {
  const app = makeApp(a => a.use(csrfMiddleware({ secret: SECRET })));

  const g = await app.handle(new Request('http://localhost/ping'));
  assert.equal(g.status, 200);
  const setCookie = g.headers.get('set-cookie');
  const token = setCookie?.match(/__Host-csrf=([^;]+)/)?.[1];
  assert.ok(token, 'CSRF cookie should be issued on GET');

  const bad = await app.handle(
    new Request('http://localhost/echo', {
      method: 'POST',
      headers: { cookie: `__Host-csrf=${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    }),
  );
  assert.equal(bad.status, 403);

  const ok = await app.handle(
    new Request('http://localhost/echo', {
      method: 'POST',
      headers: {
        cookie: `__Host-csrf=${token}`,
        'x-csrf-token': token,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ x: 1 }),
    }),
  );
  assert.equal(ok.status, 200);
});

test('elysia: securityMiddleware composes all four', async () => {
  const store = rateLimit.stores.memory();
  const app = makeApp(a =>
    a.use(
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

  const res = await app.handle(
    new Request('http://localhost/ping', {
      headers: { origin: 'https://app.example.com' },
    }),
  );
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('access-control-allow-origin'), 'https://app.example.com');
  assert.ok(res.headers.get('x-ratelimit-remaining'));
  store._stop();
});
