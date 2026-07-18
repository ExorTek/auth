import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { appendSetCookieHeader } from '../src/http.js';

describe('appendSetCookieHeader', () => {
  test('undefined → returns new value as string', () => {
    assert.equal(appendSetCookieHeader(undefined, 'a=1'), 'a=1');
  });

  test('null → returns new value as string', () => {
    assert.equal(appendSetCookieHeader(null, 'a=1'), 'a=1');
  });

  test('empty string → returns new value as string', () => {
    // Empty string is falsy; treat like "nothing there yet".
    assert.equal(appendSetCookieHeader('', 'a=1'), 'a=1');
  });

  test('single existing string → returns [existing, value]', () => {
    assert.deepEqual(appendSetCookieHeader('a=1', 'b=2'), ['a=1', 'b=2']);
  });

  test('existing array → returns copy with value appended', () => {
    const existing = ['a=1', 'b=2'];
    const out = appendSetCookieHeader(existing, 'c=3');
    assert.deepEqual(out, ['a=1', 'b=2', 'c=3']);
    // Does not mutate the input.
    assert.deepEqual(existing, ['a=1', 'b=2']);
  });
});
