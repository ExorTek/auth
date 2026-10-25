import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

import { fetchCapped } from '../src/fetch-capped.js';

const fail = (reason, message) => Object.assign(new Error(message), { reason });

const server = createServer((req, res) => {
  if (req.url === '/drip') {
    // Headers immediately, then one byte every 100 ms — forever.
    res.writeHead(200, { 'content-type': 'application/json' });
    const t = setInterval(() => res.write(' '), 100);
    res.on('close', () => clearInterval(t));
    return;
  }
  if (req.url === '/big') {
    res.writeHead(200); // chunked, no content-length
    res.end('x'.repeat(10_000));
    return;
  }
  if (req.url === '/redirect') {
    res.writeHead(302, { location: 'http://169.254.169.254/' });
    res.end();
    return;
  }
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end('{"ok":true}');
});
await new Promise(r => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;
after(() => server.close());

test('fetchCapped: the deadline covers a body that is still dripping', async () => {
  const started = Date.now();
  await assert.rejects(fetchCapped(`${base}/drip`, {}, { timeoutMs: 300, maxBytes: 1_000_000, fail }), {
    reason: 'timeout',
  });
  assert.ok(Date.now() - started < 2000);
});

test('fetchCapped: an undeclared oversized body stops at maxBytes', async () => {
  await assert.rejects(fetchCapped(`${base}/big`, {}, { timeoutMs: 2000, maxBytes: 1000, fail }), {
    reason: 'too_large',
  });
});

test('fetchCapped: redirects are refused', async () => {
  await assert.rejects(fetchCapped(`${base}/redirect`, {}, { timeoutMs: 2000, maxBytes: 1000, fail }), {
    reason: 'redirect',
  });
});

test('fetchCapped: returns the response and text', async () => {
  const { response, text } = await fetchCapped(`${base}/ok`, {}, { timeoutMs: 2000, maxBytes: 1000, fail });
  assert.equal(response.status, 200);
  assert.deepEqual(JSON.parse(text), { ok: true });
});
