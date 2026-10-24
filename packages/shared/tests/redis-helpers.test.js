import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createRedisHelpers } from '../src/redis-helpers.js';

/** Records SET calls; `existing` keys make an NX set fail like Redis does. */
function recorder(extra = {}, existing = new Set()) {
  const calls = [];
  return {
    calls,
    client: {
      async set(key, value, ...opts) {
        calls.push(opts);
        const nx = opts.includes('NX') || opts[0]?.NX === true;
        if (nx && existing.has(key)) {
          return null;
        }
        existing.add(key);
        return 'OK';
      },
      ...extra,
    },
  };
}

test('setIfAbsent dispatches NX per dialect and reports who won', async () => {
  const io = recorder({ status: 'ready' });
  const ioHelpers = createRedisHelpers(io.client);
  assert.equal(await ioHelpers.setIfAbsent('k', '1', 1000), true);
  assert.equal(await ioHelpers.setIfAbsent('k', '1', 1000), false);
  assert.deepEqual(io.calls[0], ['PX', 1000, 'NX']);

  const nr = recorder();
  const nrHelpers = createRedisHelpers(nr.client);
  assert.equal(await nrHelpers.setIfAbsent('k', '1', 1000), true);
  assert.equal(await nrHelpers.setIfAbsent('k', '1', 1000), false);
  assert.deepEqual(nr.calls[0], [{ PX: 1000, NX: true }]);
});

test('setKeepTTL dispatches KEEPTTL per dialect', async () => {
  const io = recorder({ status: 'ready' });
  await createRedisHelpers(io.client).setKeepTTL('k', 'v');
  assert.deepEqual(io.calls[0], ['KEEPTTL']);

  const nr = recorder();
  await createRedisHelpers(nr.client).setKeepTTL('k', 'v');
  assert.deepEqual(nr.calls[0], [{ KEEPTTL: true }]);
});
