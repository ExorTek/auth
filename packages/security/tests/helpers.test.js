import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  getClientIp,
  bearer,
  checkOrigin,
  webhookVerify,
  webhookVerifyStripe,
  sanitizeBody,
  sanitizeParams,
  safeJoin,
  sanitizeFilename,
  freezePrototypes,
  timeout,
  bodyLimit,
  honeypot,
  slowDown,
  rateLimit,
  SecurityError,
  ErrorCode,
} from '../src/index.js';

// getClientIp

test('getClientIp: returns socket.remoteAddress when trustProxy=false', () => {
  const req = { socket: { remoteAddress: '10.0.0.1' }, headers: { 'x-forwarded-for': '1.2.3.4' } };
  assert.equal(getClientIp(req), '10.0.0.1');
});

test('getClientIp: honours X-Forwarded-For when trustProxy=true', () => {
  const req = { socket: { remoteAddress: '10.0.0.1' }, headers: { 'x-forwarded-for': '1.2.3.4, 10.0.0.2' } };
  assert.equal(getClientIp(req, { trustProxy: true }), '1.2.3.4');
});

test('getClientIp: ignores XFF when remote not in trusted list', () => {
  const req = { socket: { remoteAddress: '10.0.0.99' }, headers: { 'x-forwarded-for': '1.2.3.4' } };
  assert.equal(getClientIp(req, { trustProxy: ['10.0.0.1'] }), '10.0.0.99');
});

test('getClientIp: falls back gracefully with no info', () => {
  assert.equal(getClientIp({}), undefined);
});

test('getClientIp: trustProxy=list walks right-to-left, skipping trusted hops (spoof-resistant)', () => {
  // Attacker spoofs a leading XFF entry. Chain: client → real-lb → node.
  // Correct answer: 203.0.113.42 (the last untrusted hop), NOT the spoofed
  // '1.2.3.4' the attacker put at the front.
  const req = {
    socket: { remoteAddress: '10.0.0.1' },
    headers: { 'x-forwarded-for': '1.2.3.4, 203.0.113.42, 10.0.0.2' },
  };
  assert.equal(getClientIp(req, { trustProxy: ['10.0.0.1', '10.0.0.2'] }), '203.0.113.42');
});

test('getClientIp: trustProxy=list — every hop trusted falls back to left-most', () => {
  const req = {
    socket: { remoteAddress: '10.0.0.1' },
    headers: { 'x-forwarded-for': '10.0.0.2, 10.0.0.3' },
  };
  assert.equal(getClientIp(req, { trustProxy: ['10.0.0.1', '10.0.0.2', '10.0.0.3'] }), '10.0.0.2');
});

test('getClientIp: proxyCount=N skips N rightmost hops', () => {
  const req = {
    socket: { remoteAddress: '10.0.0.1' },
    headers: { 'x-forwarded-for': '1.2.3.4, 203.0.113.42, 172.16.0.5, 10.0.0.2' },
  };
  // 2 trusted proxy hops from the right → return the 3rd-from-right
  assert.equal(getClientIp(req, { proxyCount: 2 }), '203.0.113.42');
});

test('getClientIp: proxyCount=0 returns the right-most hop', () => {
  const req = { headers: { 'x-forwarded-for': '1.2.3.4, 203.0.113.42, 10.0.0.2' } };
  assert.equal(getClientIp(req, { proxyCount: 0 }), '10.0.0.2');
});

test('getClientIp: proxyCount larger than chain returns left-most', () => {
  const req = { headers: { 'x-forwarded-for': '1.2.3.4, 203.0.113.42' } };
  assert.equal(getClientIp(req, { proxyCount: 5 }), '1.2.3.4');
});

// bearer

test('bearer: parses `Bearer <token>` case-insensitively', () => {
  assert.equal(bearer('Bearer abc123'), 'abc123');
  assert.equal(bearer('bearer xyz'), 'xyz');
  assert.equal(bearer('BEARER q'), 'q');
});

test('bearer: rejects other schemes and malformed input', () => {
  assert.equal(bearer('Basic YWJjOjEyMw=='), null);
  assert.equal(bearer('Bearer '), null);
  assert.equal(bearer('Bearer'), null);
  assert.equal(bearer(''), null);
  assert.equal(bearer(undefined), null);
});

// checkOrigin

test('checkOrigin: safe methods pass without an Origin header', () => {
  const opts = { allowedOrigins: ['https://app.example.com'] };
  assert.equal(checkOrigin({ method: 'GET', headers: {} }, opts), true);
  assert.equal(checkOrigin({ method: 'HEAD', headers: {} }, opts), true);
});

test('checkOrigin: unsafe methods require a matching Origin', () => {
  const opts = { allowedOrigins: ['https://app.example.com'] };
  assert.equal(checkOrigin({ method: 'POST', headers: { origin: 'https://app.example.com' } }, opts), true);
  assert.equal(checkOrigin({ method: 'POST', headers: { origin: 'https://evil.com' } }, opts), false);
  // Missing Origin on unsafe method → deny.
  assert.equal(checkOrigin({ method: 'POST', headers: {} }, opts), false);
});

test('checkOrigin: falls back to Referer', () => {
  const opts = { allowedOrigins: ['https://app.example.com'] };
  assert.equal(checkOrigin({ method: 'POST', headers: { referer: 'https://app.example.com/settings' } }, opts), true);
});

test('checkOrigin: RegExp allowlist supported', () => {
  const opts = { allowedOrigins: [/^https:\/\/[a-z]+\.example\.com$/] };
  assert.equal(checkOrigin({ method: 'POST', headers: { origin: 'https://app.example.com' } }, opts), true);
  assert.equal(checkOrigin({ method: 'POST', headers: { origin: 'https://evil.example.org' } }, opts), false);
});

// webhookVerify

test('webhookVerify: accepts a matching hex signature', () => {
  const secret = 'x'.repeat(32);
  const payload = 'hello';
  const sig = createHmac('sha256', secret).update(payload).digest('hex');
  assert.equal(webhookVerify(payload, sig, secret), true);
});

test('webhookVerify: accepts scheme-prefixed signatures', () => {
  const secret = 'x'.repeat(32);
  const payload = '{"event":"x"}';
  const hex = createHmac('sha256', secret).update(payload).digest('hex');
  assert.equal(webhookVerify(payload, `sha256=${hex}`, secret), true);
  // Stripe-style multi-value envelope.
  assert.equal(webhookVerify(payload, `t=123456,v1=${hex}`, secret), true);
});

test('webhookVerify: rejects wrong signature', () => {
  const secret = 'x'.repeat(32);
  const payload = 'hello';
  assert.equal(webhookVerify(payload, '0'.repeat(64), secret), false);
});

test('webhookVerify: rejects malformed input', () => {
  const secret = 'x'.repeat(32);
  assert.equal(webhookVerify('x', '', secret), false);
  assert.equal(webhookVerify('x', 'not-hex', secret), false);
  assert.throws(() => webhookVerify('x', 'aa', ''), SecurityError);
});

test('webhookVerify: sha512 works', () => {
  const secret = 'k'.repeat(32);
  const payload = 'body';
  const hex = createHmac('sha512', secret).update(payload).digest('hex');
  assert.equal(webhookVerify(payload, hex, secret, { algorithm: 'sha512' }), true);
});

test('webhookVerify: rejects algorithms outside the allowlist', () => {
  const secret = 'k'.repeat(32);
  for (const bad of ['sha1', 'md5', 'sha384', 'SHA256', '']) {
    assert.throws(
      () => webhookVerify('body', 'aa', secret, { algorithm: bad }),
      err => err instanceof SecurityError && err.code === ErrorCode.INVALID_ARGUMENT && /sha256.*sha512/.test(err.message),
    );
  }
});

// webhookVerifyStripe

function stripeSign(payload, secret, t = 1_700_000_000) {
  const signed = `${t}.${payload}`;
  const v1 = createHmac('sha256', secret).update(signed).digest('hex');
  return { t, v1, header: `t=${t},v1=${v1}` };
}

test('webhookVerifyStripe: accepts a fresh valid envelope', () => {
  const secret = 'whsec_'.padEnd(40, 'x');
  const { t, header } = stripeSign('body', secret);
  assert.equal(webhookVerifyStripe('body', header, secret, { now: t }), true);
});

test('webhookVerifyStripe: within tolerance window', () => {
  const secret = 'whsec_'.padEnd(40, 'x');
  const { t, header } = stripeSign('body', secret);
  // Default tolerance = 300s; ±299s must pass.
  assert.equal(webhookVerifyStripe('body', header, secret, { now: t + 299 }), true);
  assert.equal(webhookVerifyStripe('body', header, secret, { now: t - 299 }), true);
});

test('webhookVerifyStripe: outside tolerance window fails', () => {
  const secret = 'whsec_'.padEnd(40, 'x');
  const { t, header } = stripeSign('body', secret);
  assert.equal(webhookVerifyStripe('body', header, secret, { now: t + 301 }), false);
  assert.equal(webhookVerifyStripe('body', header, secret, { now: t - 301 }), false);
});

test('webhookVerifyStripe: custom tolerance', () => {
  const secret = 'whsec_'.padEnd(40, 'x');
  const { t, header } = stripeSign('body', secret);
  assert.equal(webhookVerifyStripe('body', header, secret, { tolerance: 10, now: t + 5 }), true);
  assert.equal(webhookVerifyStripe('body', header, secret, { tolerance: 10, now: t + 11 }), false);
});

test('webhookVerifyStripe: rejects tampered signature', () => {
  const secret = 'whsec_'.padEnd(40, 'x');
  const { t, header } = stripeSign('body', secret);
  const tampered = header.replace(/v1=[0-9a-f]+/, 'v1=' + '0'.repeat(64));
  assert.equal(webhookVerifyStripe('body', tampered, secret, { now: t }), false);
});

test('webhookVerifyStripe: rejects tampered payload', () => {
  const secret = 'whsec_'.padEnd(40, 'x');
  const { t, header } = stripeSign('body', secret);
  assert.equal(webhookVerifyStripe('altered', header, secret, { now: t }), false);
});

test('webhookVerifyStripe: header missing t or v1 fails without throwing', () => {
  const secret = 'whsec_'.padEnd(40, 'x');
  const { v1 } = stripeSign('body', secret);
  assert.equal(webhookVerifyStripe('body', `v1=${v1}`, secret), false);
  assert.equal(webhookVerifyStripe('body', 't=1700000000', secret), false);
  assert.equal(webhookVerifyStripe('body', '', secret), false);
});

test('webhookVerifyStripe: multiple v1 candidates + secret rotation', () => {
  const [oldSecret, newSecret] = ['old_' + 'x'.repeat(36), 'new_' + 'x'.repeat(36)];
  const t = 1_700_000_000;
  const oldV1 = createHmac('sha256', oldSecret).update(`${t}.body`).digest('hex');
  const newV1 = createHmac('sha256', newSecret).update(`${t}.body`).digest('hex');
  const header = `t=${t},v1=${oldV1},v1=${newV1}`;
  // Either secret verifies (rotation).
  assert.equal(webhookVerifyStripe('body', header, oldSecret, { now: t }), true);
  assert.equal(webhookVerifyStripe('body', header, newSecret, { now: t }), true);
  // Array-form secret rotation also verifies.
  assert.equal(webhookVerifyStripe('body', header, [oldSecret, newSecret], { now: t }), true);
});

test('webhookVerifyStripe: ignores unknown keys and legacy v0', () => {
  const secret = 'whsec_'.padEnd(40, 'x');
  const { t, v1 } = stripeSign('body', secret);
  const header = `t=${t},v0=deadbeef,v1=${v1},unknown=whatever`;
  assert.equal(webhookVerifyStripe('body', header, secret, { now: t }), true);
});

test('webhookVerifyStripe: rejects invalid options', () => {
  const secret = 'whsec_'.padEnd(40, 'x');
  const { header } = stripeSign('body', secret);
  assert.throws(() => webhookVerifyStripe('body', header, secret, { tolerance: 0 }), SecurityError);
  assert.throws(() => webhookVerifyStripe('body', header, secret, { tolerance: -1 }), SecurityError);
  assert.throws(() => webhookVerifyStripe('body', header, secret, { tolerance: NaN }), SecurityError);
  assert.throws(() => webhookVerifyStripe('body', header, []), SecurityError);
  assert.throws(() => webhookVerifyStripe('body', header, [null]), SecurityError);
});

// sanitizeBody

test('sanitizeBody: strips MongoDB operator keys', () => {
  const out = sanitizeBody({ $ne: 1, name: 'ok', nested: { $gt: 2, safe: 3 } });
  assert.deepEqual(out, { name: 'ok', nested: { safe: 3 } });
});

test('sanitizeBody: strips dotted keys', () => {
  const out = sanitizeBody({ 'a.b': 1, plain: 2 });
  assert.deepEqual(out, { plain: 2 });
});

test('sanitizeBody: rejects mode throws on suspicious keys', () => {
  assert.throws(() => sanitizeBody({ $where: 'evil' }, { mode: 'reject' }), SecurityError);
});

test('sanitizeBody: refuses to walk beyond maxDepth', () => {
  let deep = { v: 1 };
  for (let i = 0; i < 20; i++) {
    deep = { nested: deep };
  }
  assert.throws(() => sanitizeBody(deep, { maxDepth: 5 }), SecurityError);
});

test('sanitizeBody: walks arrays and preserves scalars', () => {
  const out = sanitizeBody([{ $x: 1, y: 2 }, 'string', 42]);
  assert.deepEqual(out, [{ y: 2 }, 'string', 42]);
});

// sanitizeParams

test('sanitizeParams: default mode=first collapses duplicates to first value', () => {
  assert.deepEqual(sanitizeParams({ x: ['a', 'b'], y: 'z' }), { x: 'a', y: 'z' });
});

test('sanitizeParams: last mode picks trailing', () => {
  assert.deepEqual(sanitizeParams({ x: ['a', 'b'] }, { mode: 'last' }), { x: 'b' });
});

test('sanitizeParams: array mode preserves', () => {
  assert.deepEqual(sanitizeParams({ x: ['a', 'b'] }, { mode: 'array' }), { x: ['a', 'b'] });
});

test('sanitizeParams: rejects payloads over maxParams', () => {
  const big = {};
  for (let i = 0; i < 20; i++) {
    big[`k${i}`] = 'v';
  }
  assert.throws(() => sanitizeParams(big, { maxParams: 10 }), SecurityError);
});

// safeJoin

test('safeJoin: joins clean segments', () => {
  const base = mkdtempSync(join(tmpdir(), 'safejoin-'));
  const result = safeJoin(base, 'sub', 'file.txt');
  assert.ok(result.endsWith('sub' + '/' + 'file.txt') || result.includes('sub'));
});

test('safeJoin: rejects .. traversal', () => {
  const base = mkdtempSync(join(tmpdir(), 'safejoin-'));
  assert.throws(() => safeJoin(base, '..', 'etc', 'passwd'), SecurityError);
  assert.throws(() => safeJoin(base, 'sub', '..', '..', 'root'), SecurityError);
});

test('safeJoin: rejects absolute-path segments that escape', () => {
  const base = mkdtempSync(join(tmpdir(), 'safejoin-'));
  assert.throws(() => safeJoin(base, '/etc/passwd'), SecurityError);
});

test('safeJoin: rejects NUL bytes', () => {
  const base = mkdtempSync(join(tmpdir(), 'safejoin-'));
  assert.throws(() => safeJoin(base, 'file\0.txt'), SecurityError);
});

// sanitizeFilename

test('sanitizeFilename: strips path separators', () => {
  assert.equal(sanitizeFilename('../etc/passwd'), 'passwd');
  assert.equal(sanitizeFilename('C:\\Windows\\notepad.exe'), 'notepad.exe');
});

test('sanitizeFilename: strips control chars and illegal punctuation', () => {
  const out = sanitizeFilename('file<>:"|?.txt');
  assert.doesNotMatch(out, /[<>:"|?]/);
});

test('sanitizeFilename: renames reserved Windows names', () => {
  assert.notEqual(sanitizeFilename('CON.txt'), 'CON.txt');
  assert.notEqual(sanitizeFilename('NUL'), 'NUL');
});

test('sanitizeFilename: returns fallback when empty', () => {
  assert.equal(sanitizeFilename('...'), 'file');
  assert.equal(sanitizeFilename(''), 'file');
});

test('sanitizeFilename: caps length', () => {
  const long = 'a'.repeat(500) + '.txt';
  assert.ok(sanitizeFilename(long).length <= 255);
});

// freezePrototypes

test('freezePrototypes: freezes core prototypes idempotently', () => {
  const first = freezePrototypes();
  assert.ok(first >= 0);
  assert.equal(Object.isFrozen(Object.prototype), true);
  // Second call should be a no-op (or return 0 net additions).
  const second = freezePrototypes();
  assert.equal(second, 0);
  // Attempting pollution silently fails in sloppy, throws in strict.
  assert.throws(() => {
    'use strict';
    Object.prototype.polluted = 42;
  });
});

test('freezePrototypes: exclude drops named defaults without freezing them', () => {
  // Two disjoint sandbox prototypes so we can verify exclude by
  // observing the additional-freeze count. Using `additional`
  // isolates us from whatever the base test above already froze.
  class Sandbox1 {}
  class Sandbox2 {}
  const additional = [Sandbox1.prototype, Sandbox2.prototype];
  const withoutExclude = freezePrototypes({ additional });
  assert.equal(withoutExclude, 2, 'sandboxes freeze on first pass');
  // Exclude with names not in defaults is a no-op — the defaults path
  // still short-circuits on already-frozen prototypes, and the
  // additional list is empty this time.
  assert.equal(freezePrototypes({ exclude: ['Bogus'] }), 0);
  // Exclude with real names is silently accepted (Date/RegExp are
  // already frozen by the earlier test, so nothing to observe in the
  // count — the contract is that the call does not throw).
  assert.doesNotThrow(() => freezePrototypes({ exclude: ['Date', 'RegExp'] }));
});

// timeout

test('timeout: resolves when promise settles before deadline', async () => {
  const result = await timeout(Promise.resolve('ok'), 100);
  assert.equal(result, 'ok');
});

test('timeout: rejects with REQUEST_TIMEOUT when deadline hits', async () => {
  await assert.rejects(
    () => timeout(new Promise(() => {}), 20, { label: 'test' }),
    err => err instanceof SecurityError && /timed out/.test(err.message),
  );
});

test('timeout: rejects on invalid ms', () => {
  assert.throws(() => timeout(Promise.resolve(1), 0), SecurityError);
  assert.throws(() => timeout(Promise.resolve(1), -1), SecurityError);
});

// bodyLimit

test('bodyLimit: accepts under-limit lengths', () => {
  assert.deepEqual(bodyLimit(100, 1000), { ok: true });
});

test('bodyLimit: rejects over-limit', () => {
  const r = bodyLimit(2000, 1000);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'too-large');
});

test('bodyLimit: missing content-length is ambiguous but allowed', () => {
  const r = bodyLimit(undefined, 1000);
  assert.equal(r.ok, true);
  assert.equal(r.reason, 'missing');
});

test('bodyLimit: rejects invalid content-length', () => {
  assert.equal(bodyLimit('not-a-number', 1000).ok, false);
  assert.equal(bodyLimit(-1, 1000).ok, false);
});

test('bodyLimit: rejects malformed config', () => {
  assert.throws(() => bodyLimit(100, -1), SecurityError);
});

// honeypot

test('honeypot: default field=website — filled triggers bot flag', () => {
  assert.equal(honeypot({ email: 'a@b.com', website: 'evil.com' }), true);
  assert.equal(honeypot({ email: 'a@b.com', website: '' }), false);
  assert.equal(honeypot({ email: 'a@b.com' }), false);
});

test('honeypot: custom field name', () => {
  assert.equal(honeypot({ trap: 'x' }, { fieldName: 'trap' }), true);
});

test('honeypot: caseInsensitive matches case variants', () => {
  assert.equal(honeypot({ WEBSITE: 'x' }, { caseInsensitive: true }), true);
  assert.equal(honeypot({ WEBSITE: 'x' }), false);
});

// slowDown

test('slowDown: allows all requests, adds delay after threshold', async () => {
  const store = rateLimit.stores.memory();
  const throttle = slowDown({
    store,
    window: '1m',
    delayAfter: 2,
    delayMs: 10,
    maxDelayMs: 100,
  });

  const r1 = await throttle.check({ key: 'k' });
  const r2 = await throttle.check({ key: 'k' });
  const t = Date.now();
  const r3 = await throttle.check({ key: 'k' });
  const elapsed = Date.now() - t;
  assert.equal(r1.allowed, true);
  assert.equal(r1.delayMs, 0);
  assert.equal(r2.delayMs, 0);
  assert.equal(r3.allowed, true);
  assert.ok(r3.delayMs >= 10);
  assert.ok(elapsed >= 10);
  store._stop();
});

test('slowDown: exponential growth backs off aggressively', async () => {
  const store = rateLimit.stores.memory();
  const throttle = slowDown({
    store,
    window: '1m',
    delayAfter: 0,
    delayMs: 5,
    maxDelayMs: 100,
    growth: 'exponential',
  });
  const r1 = await throttle.check({ key: 'k' });
  const r2 = await throttle.check({ key: 'k' });
  const r3 = await throttle.check({ key: 'k' });
  assert.equal(r1.delayMs, 5); // 5 * 2^0
  assert.equal(r2.delayMs, 10); // 5 * 2^1
  assert.equal(r3.delayMs, 20); // 5 * 2^2
  store._stop();
});

test('slowDown: caps delay at maxDelayMs', async () => {
  const store = rateLimit.stores.memory();
  const throttle = slowDown({
    store,
    window: '1m',
    delayAfter: 0,
    delayMs: 1000,
    maxDelayMs: 50,
  });
  const r = await throttle.check({ key: 'k' });
  assert.ok(r.delayMs <= 50);
  store._stop();
});

test('slowDown: rejects invalid config', () => {
  const store = rateLimit.stores.memory();
  assert.throws(() => slowDown({ store, window: '1m', delayAfter: -1, delayMs: 10 }), SecurityError);
  assert.throws(() => slowDown({ store, window: 'bad', delayAfter: 0, delayMs: 10 }), SecurityError);
  assert.throws(() => slowDown({}), SecurityError);
  store._stop();
});
