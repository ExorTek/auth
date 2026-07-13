import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sessionMiddleware } from '../../src/middleware/express.js';

const SECRET = 'thirty-two-byte-secret-for-session-tests';

// Minimal Express-shaped request/response mocks.
function mkReq(cookie) {
  return {
    headers: cookie ? { cookie } : {},
  };
}
function mkRes() {
  const headers = {};
  return {
    setHeader(name, value) {
      headers[name] = value;
    },
    getHeader(name) {
      return headers[name];
    },
    get __headers() {
      return headers;
    },
  };
}

test('express: populates req.session on valid cookie', async () => {
  const { manager, middleware } = sessionMiddleware({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
  });
  const { token } = await manager.issue({ userId: 'u1' });
  const req = mkReq(`__Host-sid=${encodeURIComponent(token)}`);
  const res = mkRes();
  await new Promise((resolve, reject) => middleware(req, res, err => (err ? reject(err) : resolve())));
  assert.equal(req.session?.userId, 'u1');
  assert.equal(req.sessions, manager);
  manager.store._stop();
});

test('express: req.session is null for missing cookie', async () => {
  const { manager, middleware } = sessionMiddleware({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
  });
  const req = mkReq();
  const res = mkRes();
  await new Promise((resolve, reject) => middleware(req, res, err => (err ? reject(err) : resolve())));
  assert.equal(req.session, null);
  manager.store._stop();
});

test('express: setSessionCookie writes Set-Cookie without clobbering existing', async () => {
  const { manager, middleware } = sessionMiddleware({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
  });
  const req = mkReq();
  const res = mkRes();
  res.setHeader('Set-Cookie', 'other=1');
  await new Promise((resolve, reject) => middleware(req, res, err => (err ? reject(err) : resolve())));
  res.setSessionCookie('__Host-sid=abc; Path=/; Secure');
  const val = res.__headers['Set-Cookie'];
  assert.ok(Array.isArray(val));
  assert.equal(val.length, 2);
  manager.store._stop();
});

test('express: clearSessionCookie installs delete-cookie header', async () => {
  const { manager, middleware } = sessionMiddleware({
    secret: SECRET,
    ttl: '7d',
    idleTtl: '30m',
  });
  const { token } = await manager.issue({ userId: 'u1' });
  const req = mkReq(`__Host-sid=${encodeURIComponent(token)}`);
  const res = mkRes();
  await new Promise((resolve, reject) => middleware(req, res, err => (err ? reject(err) : resolve())));
  await res.clearSessionCookie();
  const val = res.__headers['Set-Cookie'];
  assert.ok(val.includes('Max-Age=0') || (Array.isArray(val) && val.some(v => v.includes('Max-Age=0'))));
  manager.store._stop();
});

test('express: accepts a pre-built manager', async () => {
  const { createSessionManager } = await import('../../src/index.js');
  const manager = createSessionManager({ secret: SECRET, ttl: '7d', idleTtl: '30m' });
  const { middleware, manager: attached } = sessionMiddleware(manager);
  assert.equal(attached, manager);
  const req = mkReq();
  const res = mkRes();
  await new Promise((resolve, reject) => middleware(req, res, err => (err ? reject(err) : resolve())));
  manager.store._stop();
});
