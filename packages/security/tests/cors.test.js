import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cors, SecurityError } from '../src/index.js';

// origin matching

test('cors: reflect-any-origin default emits * for simple requests', () => {
  const check = cors();
  const d = check({ method: 'GET', origin: 'https://a.example' });
  assert.equal(d.headers['Access-Control-Allow-Origin'], '*');
  assert.equal(d.headers.Vary, undefined, 'no Vary needed with * (fast path)');
  assert.equal(d.allowed, true);
});

test('cors: string allowlist echoes origin + emits Vary', () => {
  const check = cors({ origin: 'https://app.example.com' });
  const d = check({ method: 'GET', origin: 'https://app.example.com' });
  assert.equal(d.headers['Access-Control-Allow-Origin'], 'https://app.example.com');
  assert.equal(d.headers.Vary, 'Origin');
  assert.equal(d.allowed, true);
});

test('cors: string allowlist rejects other origins', () => {
  const check = cors({ origin: 'https://app.example.com' });
  const d = check({ method: 'GET', origin: 'https://evil.com' });
  assert.equal(d.allowed, false);
  assert.equal(d.headers['Access-Control-Allow-Origin'], undefined);
});

test('cors: array allowlist matches any entry', () => {
  const check = cors({ origin: ['https://a.com', /\.example\.com$/i] });
  assert.equal(check({ method: 'GET', origin: 'https://a.com' }).allowed, true);
  assert.equal(check({ method: 'GET', origin: 'https://sub.example.com' }).allowed, true);
  assert.equal(check({ method: 'GET', origin: 'https://b.com' }).allowed, false);
});

test('cors: function predicate is called per request', () => {
  const check = cors({ origin: o => o?.endsWith('.trusted') });
  assert.equal(check({ method: 'GET', origin: 'x.trusted' }).allowed, true);
  assert.equal(check({ method: 'GET', origin: 'x.evil' }).allowed, false);
});

test('cors: sync predicate keeps check() synchronous (no allocation)', () => {
  const check = cors({ origin: () => true });
  const d = check({ method: 'GET', origin: 'https://x' });
  // If check() were async, this would be a Promise instead of a plain object.
  assert.equal(typeof d.then, 'undefined');
  assert.equal(d.allowed, true);
});

test('cors: async predicate makes check() return a Promise', async () => {
  const seen = [];
  const check = cors({
    origin: async o => {
      // Simulate a DB lookup — micro-tick before answering.
      await Promise.resolve();
      seen.push(o);
      return o === 'https://db-approved.com';
    },
  });
  const p = check({ method: 'GET', origin: 'https://db-approved.com' });
  assert.equal(typeof p.then, 'function', 'must be a Promise for async predicate');
  const d = await p;
  assert.equal(d.allowed, true);
  assert.equal(d.headers['Access-Control-Allow-Origin'], 'https://db-approved.com');
  assert.deepEqual(seen, ['https://db-approved.com']);
});

test('cors: async predicate can reject a request', async () => {
  const check = cors({ origin: async () => false });
  const d = await check({ method: 'GET', origin: 'https://any' });
  assert.equal(d.allowed, false);
  assert.equal(d.headers['Access-Control-Allow-Origin'], undefined);
});

test('cors: async predicate works with preflight', async () => {
  const check = cors({
    origin: async o => o === 'https://app',
    methods: ['GET', 'POST'],
    credentials: true,
  });
  const d = await check({
    method: 'OPTIONS',
    origin: 'https://app',
    requestMethod: 'POST',
    requestHeaders: 'content-type',
  });
  assert.equal(d.preflight, true);
  assert.equal(d.allowed, true);
  assert.equal(d.headers['Access-Control-Allow-Origin'], 'https://app');
  assert.equal(d.headers['Access-Control-Allow-Credentials'], 'true');
});

test('cors: origin=false disables CORS entirely', () => {
  const check = cors({ origin: false });
  const d = check({ method: 'GET', origin: 'https://anything.com' });
  assert.equal(d.allowed, false);
});

test('cors: missing Origin header is treated as not-cross-origin', () => {
  const check = cors({ origin: 'https://a.com' });
  const d = check({ method: 'GET', origin: undefined });
  assert.equal(d.allowed, false);
});

// credentials

test('cors: credentials adds Allow-Credentials + forbids * echo', () => {
  const check = cors({ origin: 'https://app.example.com', credentials: true });
  const d = check({ method: 'GET', origin: 'https://app.example.com' });
  assert.equal(d.headers['Access-Control-Allow-Credentials'], 'true');
  assert.equal(d.headers['Access-Control-Allow-Origin'], 'https://app.example.com');
});

test('cors: credentials + reflect-any throws (spec violation)', () => {
  assert.throws(() => cors({ credentials: true }), SecurityError);
  assert.throws(() => cors({ credentials: true, origin: true }), SecurityError);
});

// preflight

test('cors: preflight sets Allow-Methods and echoes Allow-Headers', () => {
  const check = cors({ origin: 'https://app.example.com' });
  const d = check({
    method: 'OPTIONS',
    origin: 'https://app.example.com',
    requestMethod: 'POST',
    requestHeaders: 'content-type,authorization',
  });
  assert.equal(d.preflight, true);
  assert.equal(d.status, 204);
  assert.match(d.headers['Access-Control-Allow-Methods'], /GET/);
  assert.equal(d.headers['Access-Control-Allow-Headers'], 'content-type,authorization');
  assert.match(d.headers.Vary, /Access-Control-Request-Headers/);
});

test('cors: preflight uses static allowedHeaders when configured', () => {
  const check = cors({
    origin: 'https://app.example.com',
    allowedHeaders: ['X-Custom', 'Content-Type'],
  });
  const d = check({
    method: 'OPTIONS',
    origin: 'https://app.example.com',
    requestMethod: 'POST',
    requestHeaders: 'anything, browser, sends',
  });
  assert.equal(d.headers['Access-Control-Allow-Headers'], 'X-Custom, Content-Type');
  // Static list → no need to Vary on request-headers.
  assert.doesNotMatch(d.headers.Vary ?? '', /Access-Control-Request-Headers/);
});

test('cors: preflight custom methods list', () => {
  const check = cors({ origin: true, methods: ['GET', 'POST'] });
  const d = check({
    method: 'OPTIONS',
    origin: 'https://x.com',
    requestMethod: 'POST',
  });
  assert.equal(d.headers['Access-Control-Allow-Methods'], 'GET, POST');
});

test('cors: preflight maxAge propagates', () => {
  const check = cors({ origin: true, maxAge: 3600 });
  const d = check({
    method: 'OPTIONS',
    origin: 'https://x.com',
    requestMethod: 'GET',
  });
  assert.equal(d.headers['Access-Control-Max-Age'], '3600');
});

test('cors: OPTIONS without Access-Control-Request-Method is NOT preflight', () => {
  const check = cors({ origin: true });
  const d = check({ method: 'OPTIONS', origin: 'https://x.com' });
  assert.equal(d.preflight, false);
  assert.equal(d.headers['Access-Control-Allow-Methods'], undefined);
});

test('cors: preflight optionsSuccessStatus override', () => {
  const check = cors({ origin: true, optionsSuccessStatus: 200 });
  const d = check({
    method: 'OPTIONS',
    origin: 'https://x.com',
    requestMethod: 'GET',
  });
  assert.equal(d.status, 200);
});

// exposed headers on actual request

test('cors: exposedHeaders emitted on non-preflight only', () => {
  const check = cors({ origin: true, exposedHeaders: ['X-Total-Count', 'X-Page'] });
  const d = check({ method: 'GET', origin: 'https://x.com' });
  assert.equal(d.headers['Access-Control-Expose-Headers'], 'X-Total-Count, X-Page');
});

test('cors: exposedHeaders NOT emitted on preflight (browsers ignore it)', () => {
  const check = cors({ origin: true, exposedHeaders: ['X-Total-Count'] });
  const d = check({
    method: 'OPTIONS',
    origin: 'https://x.com',
    requestMethod: 'GET',
  });
  assert.equal(d.headers['Access-Control-Expose-Headers'], undefined);
});

// validation

test('cors: rejects negative maxAge', () => {
  assert.throws(() => cors({ maxAge: -1 }), SecurityError);
});

test('cors: rejects non-2xx optionsSuccessStatus', () => {
  assert.throws(() => cors({ optionsSuccessStatus: 500 }), SecurityError);
  assert.throws(() => cors({ optionsSuccessStatus: 100 }), SecurityError);
});
