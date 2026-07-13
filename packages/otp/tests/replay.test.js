import { test } from 'node:test';
import assert from 'node:assert/strict';
import { totp, verifyTotp } from '../src/index.js';

// A tiny in-memory store mimicking the @exortek/security store shape.
// The replay guard uses the atomic `incr` (Redis INCR) as a
// compare-and-set, so that's all we implement here.
function makeStore() {
  const map = new Map();
  function fresh(key) {
    const v = map.get(key);
    if (!v) return null;
    if (v.expiresAt <= Date.now()) {
      map.delete(key);
      return null;
    }
    return v;
  }
  return {
    async incr(key, ttlMs) {
      const existing = fresh(key);
      if (existing) {
        existing.count += 1;
        return { count: existing.count, expiresAt: existing.expiresAt };
      }
      const entry = { count: 1, expiresAt: Date.now() + ttlMs };
      map.set(key, entry);
      return { count: 1, expiresAt: entry.expiresAt };
    },
    _size: () => map.size,
  };
}

const SECRET = 'JBSWY3DPEHPK3PXP';

test('replay: first verify succeeds, second rejects same code within window', async () => {
  const store = makeStore();
  const t = 1234567890 * 1000;
  const code = totp(SECRET, { timestamp: t });

  const first = await verifyTotp(code, SECRET, {
    timestamp: t,
    window: 1,
    replay: { store, key: 'user:42' },
  });
  assert.equal(first, true);

  // Same code, few seconds later, same window → replay guard blocks.
  const second = await verifyTotp(code, SECRET, {
    timestamp: t + 5000,
    window: 1,
    replay: { store, key: 'user:42' },
  });
  assert.equal(second, false);
});

test('replay: different user with same code is not blocked', async () => {
  const store = makeStore();
  const t = 1234567890 * 1000;
  const code = totp(SECRET, { timestamp: t });

  await verifyTotp(code, SECRET, {
    timestamp: t,
    window: 1,
    replay: { store, key: 'user:1' },
  });
  const other = await verifyTotp(code, SECRET, {
    timestamp: t,
    window: 1,
    replay: { store, key: 'user:2' },
  });
  assert.equal(other, true);
});

test('replay: guard only fires on a successful verify', async () => {
  const store = makeStore();
  const t = 1234567890 * 1000;
  const wrongCode = '000000';
  const ok = await verifyTotp(wrongCode, SECRET, {
    timestamp: t,
    replay: { store, key: 'user:x' },
  });
  assert.equal(ok, false);
  assert.equal(store._size(), 0);
});
