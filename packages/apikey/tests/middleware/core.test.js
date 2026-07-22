import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createApiKey } from '../../src/index.js';
import { memoryStore } from '../../src/stores/memory.js';
import { extractKey, normalizeOptions, runApiKey } from '../../src/middleware/core.js';

function ctx(headers = {}, query = {}) {
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  return {
    getHeader: name => lower[name.toLowerCase()],
    method: 'GET',
    ip: '127.0.0.1',
    query,
  };
}

test('extractKey: bearer scheme reads Authorization: Bearer <key>', () => {
  const config = normalizeOptions({ store: memoryStore() });
  assert.equal(extractKey(ctx({ authorization: 'Bearer sk_live_abc_def' }), config), 'sk_live_abc_def');
});

test('extractKey: raw scheme reads the header value directly', () => {
  const config = normalizeOptions({
    store: memoryStore(),
    headerName: 'x-api-key',
    scheme: 'raw',
  });
  assert.equal(extractKey(ctx({ 'x-api-key': 'sk_live_abc_def' }), config), 'sk_live_abc_def');
});

test('extractKey: allowQueryParam falls back to query when header missing', () => {
  const config = normalizeOptions({
    store: memoryStore(),
    allowQueryParam: true,
  });
  assert.equal(extractKey(ctx({}, { api_key: 'sk_live_abc_def' }), config), 'sk_live_abc_def');
});

test('extractKey: custom tokenFromRequest overrides all defaults', () => {
  const config = normalizeOptions({
    store: memoryStore(),
    tokenFromRequest: () => 'sk_live_custom_impl',
  });
  assert.equal(extractKey(ctx({}), config), 'sk_live_custom_impl');
});

test('runApiKey: happy path returns { verifyResult }, no response', async () => {
  const store = memoryStore();
  const { key } = await createApiKey({ store, prefix: 'sk_live', userId: 'u1', scopes: ['read'] });
  const config = normalizeOptions({ store });
  const res = await runApiKey(ctx({ authorization: `Bearer ${key}` }), config);
  assert.equal(res.verifyResult.valid, true);
  assert.equal(res.response, undefined);
});

test('runApiKey: missing key → 401 missing_api_key', async () => {
  const config = normalizeOptions({ store: memoryStore() });
  const res = await runApiKey(ctx({}), config);
  assert.equal(res.response.status, 401);
  assert.equal(res.response.body.error, 'missing_api_key');
});

test('runApiKey: invalid → 401 invalid_api_key with reason', async () => {
  const config = normalizeOptions({ store: memoryStore() });
  const res = await runApiKey(ctx({ authorization: 'Bearer sk_live_bogus_key' }), config);
  assert.equal(res.response.status, 401);
  assert.equal(res.response.body.error, 'invalid_api_key');
});

test('runApiKey: missing_scope → 403', async () => {
  const store = memoryStore();
  const { key } = await createApiKey({ store, prefix: 'sk_live', userId: 'u', scopes: ['read'] });
  const config = normalizeOptions({ store, requiredScopes: ['write'] });
  const res = await runApiKey(ctx({ authorization: `Bearer ${key}` }), config);
  assert.equal(res.response.status, 403);
  assert.equal(res.response.body.reason, 'missing_scope');
});
