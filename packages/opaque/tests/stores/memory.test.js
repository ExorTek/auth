import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { memoryStore } from '../../src/stores/memory.js';

describe('memoryStore', () => {
  test('set + get round-trip', async () => {
    const store = memoryStore();
    await store.set('hash1', { userId: 'usr_1' });
    assert.deepEqual(await store.get('hash1'), { userId: 'usr_1' });
    store._stop();
  });

  test('get returns null for an unknown key', async () => {
    const store = memoryStore();
    assert.equal(await store.get('nope'), null);
    store._stop();
  });

  test('entries expire after expiresIn', async () => {
    const store = memoryStore();
    await store.set('hash1', { a: 1 }, { expiresIn: 5 });
    await new Promise(r => setTimeout(r, 20));
    assert.equal(await store.get('hash1'), null);
    store._stop();
  });

  test('no expiresIn means no expiry', async () => {
    const store = memoryStore();
    await store.set('hash1', { a: 1 });
    await new Promise(r => setTimeout(r, 20));
    assert.deepEqual(await store.get('hash1'), { a: 1 });
    store._stop();
  });

  test('delete removes the entry and is idempotent', async () => {
    const store = memoryStore();
    await store.set('hash1', { a: 1 });
    assert.equal(await store.delete('hash1'), true);
    assert.equal(await store.get('hash1'), null);
    assert.equal(await store.delete('hash1'), false);
    store._stop();
  });

  test('background sweep prunes expired entries', async () => {
    const store = memoryStore({ sweepMs: 10 });
    await store.set('hash1', { a: 1 }, { expiresIn: 5 });
    await new Promise(r => setTimeout(r, 30));
    assert.equal(store._size(), 0);
    store._stop();
  });
});
