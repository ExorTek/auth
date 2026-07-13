import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createHibpClient } from '../src/hibp.js';
import { PasswordError, ErrorCode } from '../src/errors.js';

// Mock fetch that returns a canned HIBP response for a given SHA-1
// prefix. HIBP's real API responds with lines of `<suffix>:<count>`.
function mockFetchWithSuffix(suffix, count) {
  return async () => ({
    ok: true,
    status: 200,
    text: async () => `${suffix}:${count}\r\nABCDEF0000000000000000000000000000000:1`,
  });
}

test('hibp.check: matched suffix → pwned true with count', async () => {
  const sha1 = createHash('sha1').update('password', 'utf8').digest('hex').toUpperCase();
  const suffix = sha1.slice(5);
  const client = createHibpClient({ fetch: mockFetchWithSuffix(suffix, 100000) });
  const r = await client.check('password');
  assert.equal(r.pwned, true);
  assert.equal(r.count, 100000);
});

test('hibp.check: unmatched suffix → pwned false', async () => {
  const client = createHibpClient({ fetch: mockFetchWithSuffix('DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEA', 42) });
  const r = await client.check('probably-not-in-hibp-random-1234567');
  assert.equal(r.pwned, false);
  assert.equal(r.count, 0);
});

test('hibp.check: network failure without failOpen → HIBP_UNAVAILABLE', async () => {
  const client = createHibpClient({
    fetch: async () => {
      throw new Error('network down');
    },
  });
  await assert.rejects(
    client.check('password'),
    err => err instanceof PasswordError && err.code === ErrorCode.HIBP_UNAVAILABLE,
  );
});

test('hibp.check: failOpen returns { pwned: false } on network failure', async () => {
  const client = createHibpClient({
    fetch: async () => {
      throw new Error('network down');
    },
  });
  const r = await client.check('password', { failOpen: true });
  assert.deepEqual(r, { pwned: false, count: 0 });
});

test('hibp.check: non-200 response → HIBP_UNAVAILABLE', async () => {
  const client = createHibpClient({
    fetch: async () => ({ ok: false, status: 503, text: async () => 'busy' }),
  });
  await assert.rejects(client.check('password'));
});

test('hibp: rejects malformed endpoint (no trailing slash)', () => {
  assert.throws(() => createHibpClient({ endpoint: 'https://api.example.com/range' }));
});

test('hibp: rejects invalid timeout', () => {
  assert.throws(() => createHibpClient({ timeoutMs: 50 }));
  assert.throws(() => createHibpClient({ timeoutMs: 999999 }));
});

test('hibp: rejects missing fetch when no global available', () => {
  // globalThis.fetch exists on Node 22 so this normally doesn't fire.
  // Verify by injecting an obviously-wrong value:
  assert.throws(() => createHibpClient({ fetch: 'not-a-function' }));
});
