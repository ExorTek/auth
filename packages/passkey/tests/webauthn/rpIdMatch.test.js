import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { matchRpId } from '../../src/webauthn/rpIdMatch.js';

function sha256(text) {
  return new Uint8Array(createHash('sha256').update(text).digest());
}

describe('rpIdMatch — matchRpId', () => {
  test('single string match', () => {
    const result = matchRpId(sha256('example.com'), 'example.com');
    assert.deepEqual(result, { matched: 'example.com' });
  });

  test('single string mismatch → null', () => {
    assert.equal(matchRpId(sha256('example.com'), 'other.com'), null);
  });

  test('array — first-match wins', () => {
    const result = matchRpId(sha256('example.co.uk'), ['example.com', 'example.co.uk', 'example.de']);
    assert.deepEqual(result, { matched: 'example.co.uk' });
  });

  test('array — none matches → null', () => {
    assert.equal(matchRpId(sha256('unrelated.io'), ['example.com', 'example.co.uk']), null);
  });

  test('rejects wrong-length hash', () => {
    assert.throws(() => matchRpId(new Uint8Array(31), 'example.com'), /32-byte/);
  });

  test('rejects non-Uint8Array hash', () => {
    assert.throws(() => matchRpId('hash', 'example.com'), /32-byte/);
  });

  test('rejects empty candidate list', () => {
    assert.throws(() => matchRpId(sha256('example.com'), []), /expectedRpId list is empty/);
  });

  test('rejects empty string candidate', () => {
    assert.throws(() => matchRpId(sha256('example.com'), ['']), /non-empty strings/);
  });
});
