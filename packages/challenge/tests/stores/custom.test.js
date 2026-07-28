import { test } from 'node:test';
import assert from 'node:assert/strict';

import { customStore } from '../../src/stores/custom.js';
import { createChallenge, verifyChallenge, ChallengeError, ErrorCode } from '../../src/index.js';

const SECRET = 'x'.repeat(32);

test('rejects a non-object impl', () => {
  assert.throws(
    () => customStore(null),
    err => err instanceof ChallengeError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('rejects an impl missing incr', () => {
  assert.throws(() => customStore({}), ChallengeError);
});

test('works end-to-end for single-use enforcement', async () => {
  const counts = new Map();
  const store = customStore({
    incr(key, ttlMs) {
      const existing = counts.get(key);
      const now = Date.now();
      if (!existing || existing.expiresAt <= now) {
        const entry = { count: 1, expiresAt: now + ttlMs };
        counts.set(key, entry);
        return entry;
      }
      existing.count += 1;
      return existing;
    },
  });

  const token = await createChallenge({ secret: SECRET, expiresIn: '5m', singleUse: true, store });
  const first = await verifyChallenge(token, { secret: SECRET, consume: true, store });
  assert.equal(first.valid, true);
  const second = await verifyChallenge(token, { secret: SECRET, consume: true, store });
  assert.deepEqual(second, { valid: false, reason: 'replay' });
});
