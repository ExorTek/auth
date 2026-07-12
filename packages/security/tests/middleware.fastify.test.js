import { test } from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import fastifyCookie from '@fastify/cookie';
import { rateLimit } from '../src/index.js';
import { securityPlugin, corsPlugin, headersPlugin, csrfPlugin, rateLimitPlugin } from '../src/middleware/fastify.js';

const SECRET = 'x'.repeat(32);

async function build(register) {
  const app = Fastify({ logger: false });
  await register(app);
  app.get('/ping', async () => ({ ok: true }));
  app.post('/echo', async req => ({ echo: req.body ?? null }));
  await app.ready();
  return app;
}

test('fastify: headersPlugin sets security headers', async () => {
  const app = await build(a => a.register(headersPlugin));
  const res = await app.inject({ method: 'GET', url: '/ping' });
  assert.equal(res.statusCode, 200);
  assert.equal(res.headers['x-content-type-options'], 'nosniff');
  assert.equal(res.headers['x-frame-options'], 'DENY');
  await app.close();
});

test('fastify: corsPlugin echoes allowlisted origin', async () => {
  const app = await build(a => a.register(corsPlugin, { origin: 'https://app.example.com' }));
  const res = await app.inject({
    method: 'GET',
    url: '/ping',
    headers: { origin: 'https://app.example.com' },
  });
  assert.equal(res.headers['access-control-allow-origin'], 'https://app.example.com');
  await app.close();
});

test('fastify: corsPlugin ends preflight with 204', async () => {
  const app = await build(a => a.register(corsPlugin, { origin: 'https://app.example.com' }));
  const res = await app.inject({
    method: 'OPTIONS',
    url: '/ping',
    headers: {
      origin: 'https://app.example.com',
      'access-control-request-method': 'POST',
      'access-control-request-headers': 'content-type',
    },
  });
  assert.equal(res.statusCode, 204);
  assert.equal(res.headers['access-control-allow-methods']?.length > 0, true);
  await app.close();
});

test('fastify: corsPlugin rejects non-allowlisted origin with 403', async () => {
  const app = await build(a => a.register(corsPlugin, { origin: 'https://app.example.com' }));
  const res = await app.inject({
    method: 'GET',
    url: '/ping',
    headers: { origin: 'https://evil.com' },
  });
  assert.equal(res.statusCode, 403);
  await app.close();
});

test('fastify: rateLimitPlugin allows under limit and denies over', async () => {
  const store = rateLimit.stores.memory();
  const app = await build(a =>
    a.register(rateLimitPlugin, {
      limiter: rateLimit.fixed({ requests: 2, window: '1m', store }),
      keyGenerator: () => 'test-key',
    }),
  );

  const r1 = await app.inject({ method: 'GET', url: '/ping' });
  const r2 = await app.inject({ method: 'GET', url: '/ping' });
  const r3 = await app.inject({ method: 'GET', url: '/ping' });
  assert.equal(r1.statusCode, 200);
  assert.equal(r2.statusCode, 200);
  assert.equal(r3.statusCode, 429);
  assert.ok(r3.headers['retry-after']);
  // Default preset is 'legacy' → X-RateLimit-Remaining is emitted.
  assert.ok(r1.headers['x-ratelimit-remaining']);
  await app.close();
  store._stop();
});

test('fastify: rateLimitPlugin honors headers preset "draft"', async () => {
  const store = rateLimit.stores.memory();
  const app = await build(a =>
    a.register(rateLimitPlugin, {
      limiter: rateLimit.fixed({ requests: 5, window: '1m', store }),
      keyGenerator: () => 'k',
      headers: 'draft',
    }),
  );
  const r = await app.inject({ method: 'GET', url: '/ping' });
  assert.ok(r.headers['ratelimit-remaining'], 'draft preset emits RateLimit-Remaining');
  assert.equal(r.headers['x-ratelimit-remaining'], undefined);
  await app.close();
  store._stop();
});

test('fastify: rateLimitPlugin honors headers: false (emit nothing)', async () => {
  const store = rateLimit.stores.memory();
  const app = await build(a =>
    a.register(rateLimitPlugin, {
      limiter: rateLimit.fixed({ requests: 5, window: '1m', store }),
      keyGenerator: () => 'k',
      headers: false,
    }),
  );
  const r = await app.inject({ method: 'GET', url: '/ping' });
  assert.equal(r.headers['x-ratelimit-remaining'], undefined);
  assert.equal(r.headers['ratelimit-remaining'], undefined);
  await app.close();
  store._stop();
});

test('fastify: rateLimitPlugin honors custom header names via object', async () => {
  const store = rateLimit.stores.memory();
  const app = await build(a =>
    a.register(rateLimitPlugin, {
      limiter: rateLimit.fixed({ requests: 5, window: '1m', store }),
      keyGenerator: () => 'k',
      headers: { remaining: 'X-Quota-Remaining', reset: false },
    }),
  );
  const r = await app.inject({ method: 'GET', url: '/ping' });
  assert.ok(r.headers['x-quota-remaining']);
  assert.equal(r.headers['x-ratelimit-reset'], undefined);
  await app.close();
  store._stop();
});

test('fastify: csrfPlugin issues cookie on GET, verifies on POST', async () => {
  const app = await build(async a => {
    await a.register(fastifyCookie);
    await a.register(csrfPlugin, { secret: SECRET });
  });

  // GET issues cookie.
  const g = await app.inject({ method: 'GET', url: '/ping' });
  assert.equal(g.statusCode, 200);
  const setCookie = g.headers['set-cookie'];
  assert.ok(setCookie, 'GET must set a CSRF cookie');
  const cookieHeader = Array.isArray(setCookie) ? setCookie[0] : setCookie;
  const cookieValue = cookieHeader.match(/__Host-csrf=([^;]+)/)?.[1];
  assert.ok(cookieValue, 'CSRF cookie value must be present');

  // POST without header → 403.
  const denied = await app.inject({
    method: 'POST',
    url: '/echo',
    headers: { cookie: `__Host-csrf=${cookieValue}` },
    payload: {},
  });
  assert.equal(denied.statusCode, 403);

  // POST with matching header → allowed.
  const ok = await app.inject({
    method: 'POST',
    url: '/echo',
    headers: {
      cookie: `__Host-csrf=${cookieValue}`,
      'x-csrf-token': cookieValue,
    },
    payload: { hello: 'world' },
  });
  assert.equal(ok.statusCode, 200);
  await app.close();
});

test('fastify: csrfPlugin throws if @fastify/cookie is not registered', async () => {
  const app = Fastify({ logger: false });
  await assert.rejects(() => app.register(csrfPlugin, { secret: SECRET }).then(() => app.ready()), /fastify\/cookie/i);
  await app.close();
});

test('fastify: securityPlugin composes all four when enabled', async () => {
  const store = rateLimit.stores.memory();
  const app = await build(async a => {
    await a.register(fastifyCookie);
    await a.register(securityPlugin, {
      headers: {},
      cors: { origin: 'https://app.example.com' },
      csrf: { secret: SECRET },
      rateLimit: {
        limiter: rateLimit.fixed({ requests: 10, window: '1m', store }),
        keyGenerator: () => 'user',
      },
    });
  });
  const res = await app.inject({
    method: 'GET',
    url: '/ping',
    headers: { origin: 'https://app.example.com' },
  });
  assert.equal(res.statusCode, 200);
  assert.equal(res.headers['x-content-type-options'], 'nosniff');
  assert.equal(res.headers['access-control-allow-origin'], 'https://app.example.com');
  assert.ok(res.headers['x-ratelimit-remaining']);
  assert.ok(res.headers['set-cookie']);
  await app.close();
  store._stop();
});
