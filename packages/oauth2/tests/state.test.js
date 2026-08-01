import assert from 'node:assert/strict';
import { test } from 'node:test';

import { OAuth2Error, randomNonce, randomState } from '../src/index.js';

test('randomState / randomNonce return url-safe 256-bit values by default', () => {
  for (const gen of [randomState, randomNonce]) {
    const value = gen();
    assert.equal(value.length, 43); // base64url(32 bytes)
    assert.match(value, /^[A-Za-z0-9_-]+$/);
    assert.notEqual(gen(), gen());
  }
});

test('byte length is configurable above the 16-byte floor', () => {
  assert.equal(randomState(64).length, 86); // base64url(64 bytes)
  assert.throws(() => randomState(8), OAuth2Error);
  assert.throws(() => randomNonce(1.5), OAuth2Error);
});
