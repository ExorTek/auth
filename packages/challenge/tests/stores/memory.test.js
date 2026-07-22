import { test } from 'node:test';
import assert from 'node:assert/strict';

import { memoryStore } from '../../src/stores/memory.js';
import { ChallengeError, ErrorCode } from '../../src/index.js';

test('incr: first call returns count 1, second returns 2', async () => {
  const store = memoryStore();
  try {
    const a = await store.incr('k', 60_000);
    const b = await store.incr('k', 60_000);
    assert.equal(a.count, 1);
    assert.equal(b.count, 2);
  } finally {
    store._stop();
  }
});

test('incr: distinct keys have independent counters', async () => {
  const store = memoryStore();
  try {
    await store.incr('a', 60_000);
    await store.incr('a', 60_000);
    const b = await store.incr('b', 60_000);
    assert.equal(b.count, 1);
  } finally {
    store._stop();
  }
});

test('incr: expired entry is treated as fresh', async () => {
  const store = memoryStore();
  try {
    await store.incr('k', 1); // expires almost immediately
    await new Promise(r => setTimeout(r, 10));
    const again = await store.incr('k', 60_000);
    assert.equal(again.count, 1);
  } finally {
    store._stop();
  }
});

test('maxKeys: least-recently-touched entry evicted when cap is exceeded', async () => {
  const store = memoryStore({ maxKeys: 2 });
  try {
    await store.incr('a', 60_000);
    await store.incr('b', 60_000);
    await store.incr('c', 60_000);
    assert.equal(store._size(), 2);
    // 'a' was inserted first and never touched again → LRU → evicted.
    const a = await store.incr('a', 60_000);
    assert.equal(a.count, 1);
  } finally {
    store._stop();
  }
});

test('LRU: repeated incr on a key refreshes its position (replay-guard warmth)', async () => {
  const store = memoryStore({ maxKeys: 2 });
  try {
    await store.incr('a', 60_000); // insert a
    await store.incr('b', 60_000); // insert b
    // Touch 'a' again — it should become the newest, so 'b' is now LRU.
    const aBump = await store.incr('a', 60_000);
    assert.equal(aBump.count, 2);
    // Insert 'c' → oldest (b) evicted, NOT 'a'.
    await store.incr('c', 60_000);
    // 'a' should still hold count=2 (tombstone preserved).
    const aStill = await store.incr('a', 60_000);
    assert.equal(aStill.count, 3);
    // 'b' was evicted — fresh count.
    const bFresh = await store.incr('b', 60_000);
    assert.equal(bFresh.count, 1);
  } finally {
    store._stop();
  }
});

test('options validation: rejects non-positive integers', () => {
  for (const bad of [0, -1, 1.5, 'x']) {
    assert.throws(
      () => memoryStore({ maxKeys: bad }),
      err => err instanceof ChallengeError && err.code === ErrorCode.INVALID_ARGUMENT,
      `maxKeys=${bad}`,
    );
  }
  for (const bad of [500, 0, 1.5]) {
    assert.throws(
      () => memoryStore({ sweepMs: bad }),
      err => err instanceof ChallengeError && err.code === ErrorCode.INVALID_ARGUMENT,
      `sweepMs=${bad}`,
    );
  }
});
