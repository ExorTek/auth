import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHistory } from '../src/history.js';
import * as scrypt from '../src/algorithms/scrypt.js';

const FAST = { N: 1 << 12 };

test('history.isReused: matches previous hash', async () => {
  const h = createHistory({ keepLast: 3 });
  const oldHash = await scrypt.hash('old-password', FAST);
  assert.equal(await h.isReused('old-password', [oldHash]), true);
});

test('history.isReused: no match on fresh password', async () => {
  const h = createHistory({ keepLast: 3 });
  const oldHash = await scrypt.hash('old-password', FAST);
  assert.equal(await h.isReused('brand-new', [oldHash]), false);
});

test('history.isReused: empty history → false', async () => {
  const h = createHistory({ keepLast: 3 });
  assert.equal(await h.isReused('anything', []), false);
});

test('history.isReused: only walks keepLast entries', async () => {
  const h = createHistory({ keepLast: 1 });
  const older = await scrypt.hash('older', FAST);
  const oldest = await scrypt.hash('oldest', FAST);
  // Newer first — the "oldest" one is outside keepLast=1 and must be ignored
  assert.equal(await h.isReused('oldest', [older, oldest]), false);
});

test('history.append prepends and trims', async () => {
  const h = createHistory({ keepLast: 3 });
  const list = ['h1', 'h2', 'h3'];
  const next = h.append('h0', list);
  assert.deepEqual(next, ['h0', 'h1', 'h2']);
});

test('history.append deduplicates the fresh hash', () => {
  const h = createHistory({ keepLast: 3 });
  const next = h.append('h1', ['h1', 'h2', 'h3']);
  // 'h1' shows up only once, at the front — the older 'h1' is dropped
  assert.deepEqual(next, ['h1', 'h2', 'h3']);
});

test('history.append does not mutate input', () => {
  const h = createHistory({ keepLast: 3 });
  const list = ['h1', 'h2'];
  h.append('h0', list);
  assert.deepEqual(list, ['h1', 'h2']);
});

test('rejects invalid keepLast', () => {
  assert.throws(() => createHistory({ keepLast: 0 }));
  assert.throws(() => createHistory({ keepLast: 100 }));
});
