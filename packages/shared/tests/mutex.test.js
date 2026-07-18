import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createKeyMutex } from '../src/concurrency/mutex.js';

test('withLock: serialises concurrent callers with the same key', async () => {
  const mutex = createKeyMutex();
  const events = [];

  const task = async (name, delayMs) => {
    events.push(`${name}:enter`);
    await new Promise(r => setTimeout(r, delayMs));
    events.push(`${name}:exit`);
    return name;
  };

  const results = await Promise.all([
    mutex.withLock('k', () => task('a', 20)),
    mutex.withLock('k', () => task('b', 5)),
    mutex.withLock('k', () => task('c', 5)),
  ]);

  assert.deepEqual(results, ['a', 'b', 'c']);
  // Interleaving would be a:enter, b:enter, ... — serial gives strict pairs.
  assert.deepEqual(events, ['a:enter', 'a:exit', 'b:enter', 'b:exit', 'c:enter', 'c:exit']);
});

test('withLock: different keys do NOT block each other', async () => {
  const mutex = createKeyMutex();
  const events = [];

  await Promise.all([
    mutex.withLock('x', async () => {
      events.push('x:enter');
      await new Promise(r => setTimeout(r, 15));
      events.push('x:exit');
    }),
    mutex.withLock('y', async () => {
      events.push('y:enter');
      await new Promise(r => setTimeout(r, 5));
      events.push('y:exit');
    }),
  ]);

  assert.equal(events[0], 'x:enter');
  assert.equal(events[1], 'y:enter');
});

test('withLock: propagates rejection but still releases the lock', async () => {
  const mutex = createKeyMutex();
  let secondRan = false;

  await Promise.allSettled([
    mutex.withLock('k', async () => {
      throw new Error('boom');
    }),
    mutex.withLock('k', async () => {
      secondRan = true;
    }),
  ]);

  assert.equal(secondRan, true);
});
