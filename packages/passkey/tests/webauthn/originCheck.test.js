import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { matchesOrigin } from '../../src/webauthn/originCheck.js';

describe('originCheck — matchesOrigin', () => {
  test('string equality', () => {
    assert.equal(matchesOrigin('https://example.com', 'https://example.com'), true);
    assert.equal(matchesOrigin('https://example.com', 'https://other.com'), false);
  });

  test('scheme / host case is not normalised', () => {
    assert.equal(matchesOrigin('HTTPS://EXAMPLE.COM', 'https://example.com'), false);
  });

  test('trailing slash is significant', () => {
    assert.equal(matchesOrigin('https://example.com', 'https://example.com/'), false);
  });

  test('array — any-of match', () => {
    const list = ['https://example.com', 'https://staging.example.com'];
    assert.equal(matchesOrigin('https://staging.example.com', list), true);
    assert.equal(matchesOrigin('https://other.com', list), false);
  });

  test('array rejects non-string members', () => {
    // Walk past a string that doesn't match, then hit the bad entry.
    assert.throws(() => matchesOrigin('other', ['a', 42]), /entries must all be strings/);
  });

  test('RegExp', () => {
    assert.equal(matchesOrigin('https://tenant-1.example.com', /^https:\/\/tenant-\d+\.example\.com$/), true);
    assert.equal(matchesOrigin('https://example.com', /^https:\/\/tenant-\d+\.example\.com$/), false);
  });

  test('native-app origin strings are opaque', () => {
    assert.equal(
      matchesOrigin('android:apk-key-hash:jjOEjTNw5Y_bY9L8t7', 'android:apk-key-hash:jjOEjTNw5Y_bY9L8t7'),
      true,
    );
    assert.equal(matchesOrigin('ios:bundle-id:com.example.app', 'ios:bundle-id:com.example.app'), true);
  });

  test('rejects unsupported actual', () => {
    assert.throws(() => matchesOrigin(42, 'x'), /actual must be a string/);
  });

  test('rejects unsupported expected', () => {
    assert.throws(() => matchesOrigin('x', 42), /string, string\[\], or RegExp/);
  });
});
