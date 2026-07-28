import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { create, verify, revoke, mask, introspectionHandler, revocationHandler, OpaqueError } from '../src/index.js';
import { memoryStore } from '../src/stores/memory.js';
import { customStore } from '../src/stores/custom.js';
import { hash as hashFn } from '@exortek/crypto';

describe('create / verify / revoke', () => {
  test('round-trips a token through the store', async () => {
    const store = memoryStore();
    const { token, hash, expiresAt } = await create({ format: 'hex', store, metadata: { userId: 'usr_1' } });
    assert.equal(typeof token, 'string');
    assert.equal(typeof hash, 'string');
    assert.equal(expiresAt, undefined);

    const result = await verify(token, { store });
    assert.deepEqual(result, { valid: true, metadata: { userId: 'usr_1' } });
  });

  test('verify returns not_found for an unknown token', async () => {
    const store = memoryStore();
    const result = await verify('deadbeef', { store });
    assert.deepEqual(result, { valid: false, reason: 'not_found' });
  });

  test('expiresIn is honored and reflected in expiresAt', async () => {
    const store = memoryStore();
    const now = Date.now();
    const { token, expiresAt } = await create({ format: 'hex', store, expiresIn: '1h', now });
    assert.equal(expiresAt.getTime(), now + 60 * 60 * 1000);

    const stillValid = await verify(token, { store });
    assert.equal(stillValid.valid, true);
  });

  test('expired token fails verify', async () => {
    const store = memoryStore();
    const { token } = await create({ format: 'hex', store, expiresIn: 5 });
    await new Promise(r => setTimeout(r, 20));
    const result = await verify(token, { store });
    assert.deepEqual(result, { valid: false, reason: 'not_found' });
  });

  test('revoke makes a token fail verify, and is idempotent', async () => {
    const store = memoryStore();
    const { token } = await create({ format: 'hex', store });
    assert.equal(await revoke(token, { store }), true);
    assert.equal((await verify(token, { store })).valid, false);
    assert.equal(await revoke(token, { store }), false);
  });

  test('throws on missing store', async () => {
    await assert.rejects(() => create({ format: 'hex' }), OpaqueError);
    await assert.rejects(() => verify('tok', {}), OpaqueError);
  });

  test('honors a non-default hashAlgo end-to-end', async () => {
    const store = memoryStore();
    const { token } = await create({ format: 'hex', store, hashAlgo: 'sha512' });
    assert.equal((await verify(token, { store, hashAlgo: 'sha512' })).valid, true);
    // Wrong algo hashes to a different key, so it should miss.
    assert.equal((await verify(token, { store })).valid, false);
  });

  test('create returns hash === hashFn(token) for the default algo', async () => {
    const store = memoryStore();
    const { token, hash } = await create({ format: 'hex', store });
    assert.equal(hash, hashFn(token, { algo: 'sha256' }));
  });

  test('store keys are hashes, not raw tokens', async () => {
    const raw = new Map();
    const spy = customStore({
      set: (k, v) => raw.set(k, v),
      get: k => raw.get(k) ?? null,
      delete: k => raw.delete(k),
    });
    const { token, hash } = await create({ format: 'hex', store: spy });
    assert.equal(raw.has(token), false, 'raw token must NOT be a key');
    assert.equal(raw.has(hash), true, 'hash IS the key');
    assert.equal(raw.size, 1);
  });
});

describe('mask', () => {
  test('masks the middle of a long token', () => {
    assert.equal(mask('abcdefghijklmnop'), 'abcd…mnop');
  });

  test('fully masks a short token', () => {
    assert.equal(mask('abcd'), '****');
  });
});

describe('introspectionHandler', () => {
  test('active: true for a valid token', async () => {
    const store = memoryStore();
    const { token } = await create({ format: 'hex', store, metadata: { userId: 'usr_1' } });
    const handler = introspectionHandler({ store });
    const result = await handler({ body: { token } });
    assert.equal(result.status, 200);
    assert.deepEqual(result.body, { userId: 'usr_1', active: true });
    assert.equal(result.headers['Content-Type'], 'application/json');
    assert.equal(result.headers['Cache-Control'], 'no-store');
  });

  test('active: false for an unknown token', async () => {
    const store = memoryStore();
    const handler = introspectionHandler({ store });
    const result = await handler({ body: { token: 'nope' } });
    assert.deepEqual(result.body, { active: false });
    assert.equal(result.status, 200);
  });

  test('active: false when body is missing the token field', async () => {
    const store = memoryStore();
    const handler = introspectionHandler({ store });
    const result = await handler({ body: {} });
    assert.deepEqual(result.body, { active: false });
  });

  test('honors a custom tokenField', async () => {
    const store = memoryStore();
    const { token } = await create({ format: 'hex', store, metadata: { userId: 'u' } });
    const handler = introspectionHandler({ store, tokenField: 'access_token' });
    const result = await handler({ body: { access_token: token } });
    assert.deepEqual(result.body, { userId: 'u', active: true });
  });

  test('caller can mutate returned headers without touching later calls', async () => {
    const store = memoryStore();
    const handler = introspectionHandler({ store });
    const first = await handler({ body: {} });
    first.headers['X-Custom'] = 'yes';
    const second = await handler({ body: {} });
    assert.equal(second.headers['X-Custom'], undefined);
  });
});

describe('introspectionHandler — store failure', () => {
  test('a throwing store still yields 200 { active: false } and fires onError', async () => {
    const err = new Error('redis down');
    const throwing = {
      get: async () => {
        throw err;
      },
      set: async () => {},
      delete: async () => false,
    };
    const seen = [];
    const handler = introspectionHandler({ store: throwing, onError: e => seen.push(e) });
    const result = await handler({ body: { token: 'anything' } });
    assert.equal(result.status, 200);
    assert.deepEqual(result.body, { active: false });
    assert.deepEqual(seen, [err]);
  });
});

describe('revocationHandler', () => {
  test('revokes a known token and returns 200 with {} body (RFC 7009 §2.2)', async () => {
    const store = memoryStore();
    const { token } = await create({ format: 'hex', store });
    const handler = revocationHandler({ store });
    const result = await handler({ body: { token } });
    assert.equal(result.status, 200);
    assert.deepEqual(result.body, {});
    assert.equal(result.headers['Cache-Control'], 'no-store');
    assert.equal((await verify(token, { store })).valid, false);
  });

  test('returns 200 {} for an unknown token too (no probing)', async () => {
    const store = memoryStore();
    const handler = revocationHandler({ store });
    const result = await handler({ body: { token: 'nope' } });
    assert.equal(result.status, 200);
    assert.deepEqual(result.body, {});
  });
});
