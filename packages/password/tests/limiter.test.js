import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createLimiter, password, PasswordError, ErrorCode } from '../src/index.js';

const deferred = () => {
  let resolve, reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};
const tick = () => new Promise(r => setImmediate(r));

test('createLimiter: runs at most `concurrency` tasks at once', async () => {
  const limit = createLimiter({ concurrency: 2 });
  const gates = [deferred(), deferred(), deferred()];
  let running = 0;
  let peak = 0;
  const results = gates.map((g, i) =>
    limit(async () => {
      running++;
      peak = Math.max(peak, running);
      await g.promise;
      running--;
      return i;
    }),
  );
  await tick();
  assert.equal(limit.active, 2);
  assert.equal(limit.pending, 1);
  gates.forEach(g => g.resolve());
  assert.deepEqual(await Promise.all(results), [0, 1, 2]);
  assert.equal(peak, 2);
  assert.equal(limit.active, 0);
});

test('createLimiter: a full queue rejects with QUEUE_FULL (503)', async () => {
  const limit = createLimiter({ concurrency: 1, maxQueue: 1 });
  const gate = deferred();
  const first = limit(() => gate.promise);
  const second = limit(async () => 'queued');
  await assert.rejects(
    limit(async () => 'shed'),
    err => {
      assert.ok(err instanceof PasswordError);
      assert.equal(err.code, ErrorCode.QUEUE_FULL);
      assert.equal(err.status, 503);
      return true;
    },
  );
  gate.resolve('first');
  assert.equal(await first, 'first');
  assert.equal(await second, 'queued');
});

test('createLimiter: a failing task frees its slot', async () => {
  const limit = createLimiter({ concurrency: 1 });
  await assert.rejects(
    limit(async () => {
      throw new Error('boom');
    }),
    /boom/,
  );
  assert.equal(await limit(async () => 'next'), 'next');
  assert.equal(limit.active, 0);
});

test('createLimiter: wraps a real verify', async () => {
  const limit = createLimiter();
  const stored = await password.scrypt.hash('correct horse');
  assert.equal(await limit(() => password.verify('correct horse', stored)), true);
});

test('createLimiter: rejects bad config and non-function tasks', async () => {
  for (const config of [{ concurrency: 0 }, { concurrency: 1.5 }, { maxQueue: -1 }, null]) {
    assert.throws(() => createLimiter(config), PasswordError);
  }
  await assert.rejects(createLimiter()(/** @type {any} */ ('nope')), PasswordError);
});
