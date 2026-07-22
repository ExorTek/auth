import { test } from 'node:test';
import assert from 'node:assert/strict';

import { memoryStore } from '../../src/stores/memory.js';

function record(id, email, extras = {}) {
  return {
    id,
    email,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60_000,
    ...extras,
  };
}

test('put + getById round-trip', async () => {
  const store = memoryStore();
  try {
    await store.put(record('id1', 'a@x.com'));
    const r = await store.getById('id1');
    assert.equal(r.id, 'id1');
    assert.equal(r.email, 'a@x.com');
  } finally {
    store._stop();
  }
});

test('put stores a copy — caller mutation cannot escape', async () => {
  const store = memoryStore();
  try {
    const r = record('id1', 'a@x.com', { metadata: { a: 1 } });
    await store.put(r);
    r.metadata.a = 999; // mutate what the caller kept
    const back = await store.getById('id1');
    assert.equal(back.metadata.a, 1);
  } finally {
    store._stop();
  }
});

test('consume: first call true, subsequent false', async () => {
  const store = memoryStore();
  try {
    await store.put(record('id1', 'a@x.com'));
    assert.equal(await store.consume('id1'), true);
    assert.equal(await store.consume('id1'), false);
  } finally {
    store._stop();
  }
});

test('consume: unknown id → false', async () => {
  const store = memoryStore();
  try {
    assert.equal(await store.consume('missing'), false);
  } finally {
    store._stop();
  }
});

test('listByEmail: returns every record for the email', async () => {
  const store = memoryStore();
  try {
    await store.put(record('a', 'u@x.com'));
    await store.put(record('b', 'u@x.com'));
    await store.put(record('c', 'other@x.com'));
    const rows = await store.listByEmail('u@x.com');
    const ids = rows.map(r => r.id).sort();
    assert.deepEqual(ids, ['a', 'b']);
  } finally {
    store._stop();
  }
});

test('revokeByEmail: consumes every non-consumed record for the email', async () => {
  const store = memoryStore();
  try {
    await store.put(record('a', 'u@x.com'));
    await store.put(record('b', 'u@x.com'));
    await store.put(record('c', 'u@x.com'));
    await store.consume('a'); // already used
    const n = await store.revokeByEmail('u@x.com');
    assert.equal(n, 2);
  } finally {
    store._stop();
  }
});

test('incrRate: first call count=1, second count=2', async () => {
  const store = memoryStore();
  try {
    const a = await store.incrRate('u@x.com', 60_000);
    const b = await store.incrRate('u@x.com', 60_000);
    assert.equal(a.count, 1);
    assert.equal(b.count, 2);
  } finally {
    store._stop();
  }
});

test('incrRate: distinct emails are independent', async () => {
  const store = memoryStore();
  try {
    await store.incrRate('a@x.com', 60_000);
    const b = await store.incrRate('b@x.com', 60_000);
    assert.equal(b.count, 1);
  } finally {
    store._stop();
  }
});

test('incrRate: expired counter resets to 1', async () => {
  const store = memoryStore();
  try {
    await store.incrRate('u@x.com', 1);
    await new Promise(r => setTimeout(r, 10));
    const again = await store.incrRate('u@x.com', 60_000);
    assert.equal(again.count, 1);
  } finally {
    store._stop();
  }
});
