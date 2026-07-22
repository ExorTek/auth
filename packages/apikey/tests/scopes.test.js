import { test } from 'node:test';
import assert from 'node:assert/strict';

import { covers, hasAll, hasAny } from '../src/scopes.js';

test('covers: exact match', () => {
  assert.equal(covers(['read:users'], 'read:users'), true);
  assert.equal(covers(['write:posts'], 'read:users'), false);
});

test('covers: super wildcard (*)', () => {
  assert.equal(covers(['*'], 'anything'), true);
  assert.equal(covers(['*'], 'read:users'), true);
});

test('covers: namespace wildcard (read:*)', () => {
  assert.equal(covers(['read:*'], 'read:users'), true);
  assert.equal(covers(['read:*'], 'read:posts'), true);
  assert.equal(covers(['read:*'], 'write:users'), false);
  // Bare namespace doesn't match — the wildcard must resolve to a non-empty tail.
  assert.equal(covers(['read:*'], 'read:'), false);
});

test('covers: non-array / non-string inputs → false', () => {
  assert.equal(covers(null, 'read'), false);
  assert.equal(covers([], 'read'), false);
  assert.equal(covers(['read'], ''), false);
  assert.equal(covers(['read'], 42), false);
});

test('hasAll: every required must be covered', () => {
  assert.equal(hasAll(['read:*', 'write:posts'], ['read:users', 'write:posts']), true);
  assert.equal(hasAll(['read:*'], ['read:users', 'write:posts']), false);
  // Empty required → trivially true.
  assert.equal(hasAll(['read'], []), true);
});

test('hasAny: at least one required must be covered', () => {
  assert.equal(hasAny(['read:users'], ['read:users', 'write:posts']), true);
  assert.equal(hasAny(['read:users'], ['write:posts']), false);
  assert.equal(hasAny(['read:users'], []), false);
});
