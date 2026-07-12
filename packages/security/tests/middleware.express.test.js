import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import cookieParser from 'cookie-parser';
import { rateLimit } from '../src/index.js';
import {
  securityMiddleware,
  corsMiddleware,
  headersMiddleware,
  csrfMiddleware,
  rateLimitMiddleware,
} from '../src/middleware/express.js';

const SECRET = 'x'.repeat(32);

function makeApp(register) {
  const app = express();
  app.set('trust proxy', true);
  app.use(express.json());
  register(app);
  app.get('/ping', (_req, res) => res.json({ ok: true }));
  app.post('/echo', (req, res) => res.json({ echo: req.body ?? null }));
  return app;
}

async function fetchTest(app, { method = 'GET', path = '/', headers = {}, body }) {
  const server = app.listen(0);
  const { port } = server.address();
  try {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    return {
      status: res.status,
      headers: Object.fromEntries(res.headers.entries()),
      body: text ? tryJson(text) : null,
    };
  } finally {
    server.close();
  }
}

function tryJson(s) {
  try {
    return JSON.parse(s);
  } catch {
    return s;
  }
}

test('express: headersMiddleware sets security headers', async () => {
  const app = makeApp(a => a.use(headersMiddleware()));
  const r = await fetchTest(app, { path: '/ping' });
  assert.equal(r.status, 200);
  assert.equal(r.headers['x-content-type-options'], 'nosniff');
  assert.equal(r.headers['x-frame-options'], 'DENY');
});

test('express: corsMiddleware handles preflight + rejects bad origin', async () => {
  const app = makeApp(a => a.use(corsMiddleware({ origin: 'https://app.example.com' })));

  const pf = await fetchTest(app, {
    method: 'OPTIONS',
    path: '/ping',
    headers: {
      origin: 'https://app.example.com',
      'access-control-request-method': 'POST',
    },
  });
  assert.equal(pf.status, 204);

  const bad = await fetchTest(app, {
    path: '/ping',
    headers: { origin: 'https://evil.com' },
  });
  assert.equal(bad.status, 403);
});

test('express: rateLimitMiddleware denies over limit', async () => {
  const store = rateLimit.stores.memory();
  const app = makeApp(a =>
    a.use(
      rateLimitMiddleware({
        limiter: rateLimit.fixed({ requests: 2, window: '1m', store }),
        keyGenerator: () => 'k',
      }),
    ),
  );
  await fetchTest(app, { path: '/ping' });
  await fetchTest(app, { path: '/ping' });
  const r = await fetchTest(app, { path: '/ping' });
  assert.equal(r.status, 429);
  assert.ok(r.headers['retry-after']);
  store._stop();
});

test('express: csrfMiddleware issues + verifies', async () => {
  const app = makeApp(a => {
    a.use(cookieParser());
    a.use(csrfMiddleware({ secret: SECRET }));
  });

  const g = await fetchTest(app, { path: '/ping' });
  assert.equal(g.status, 200);
  const setCookie = g.headers['set-cookie'];
  const token = setCookie?.match(/__Host-csrf=([^;]+)/)?.[1];
  assert.ok(token);

  const bad = await fetchTest(app, {
    method: 'POST',
    path: '/echo',
    headers: { cookie: `__Host-csrf=${token}`, 'Content-Type': 'application/json' },
    body: {},
  });
  assert.equal(bad.status, 403);

  const ok = await fetchTest(app, {
    method: 'POST',
    path: '/echo',
    headers: {
      cookie: `__Host-csrf=${token}`,
      'x-csrf-token': token,
      'Content-Type': 'application/json',
    },
    body: { x: 1 },
  });
  assert.equal(ok.status, 200);
});

test('express: securityMiddleware composes all four', async () => {
  const store = rateLimit.stores.memory();
  const app = makeApp(a => {
    a.use(cookieParser());
    a.use(
      securityMiddleware({
        cors: { origin: 'https://app.example.com' },
        csrf: { secret: SECRET },
        rateLimit: {
          limiter: rateLimit.fixed({ requests: 10, window: '1m', store }),
          keyGenerator: () => 'k',
        },
      }),
    );
  });

  const r = await fetchTest(app, {
    path: '/ping',
    headers: { origin: 'https://app.example.com' },
  });
  assert.equal(r.status, 200);
  assert.equal(r.headers['x-content-type-options'], 'nosniff');
  assert.equal(r.headers['access-control-allow-origin'], 'https://app.example.com');
  assert.ok(r.headers['x-ratelimit-remaining']);
  store._stop();
});
