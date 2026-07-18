import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { assertRedisClient } from '../src/redis-guard.js';

const trap = msg => {
  throw new Error(`WRAPPED: ${msg}`);
};

describe('assertRedisClient', () => {
  test('rejects null / non-object client', () => {
    assert.throws(() => assertRedisClient(null, ['get'], trap), /WRAPPED: client is required/);
    assert.throws(() => assertRedisClient(undefined, ['get'], trap), /WRAPPED: client is required/);
    assert.throws(() => assertRedisClient('not-an-object', ['get'], trap), /WRAPPED: client is required/);
    assert.throws(() => assertRedisClient(42, ['get'], trap), /WRAPPED: client is required/);
  });

  test('rejects when a required method is missing', () => {
    const client = { get: () => {}, set: () => {} };
    assert.throws(
      () => assertRedisClient(client, ['get', 'set', 'del'], trap),
      /WRAPPED: client is missing 'del\(\)'/,
    );
  });

  test('rejects when a required method is present but not a function', () => {
    const client = { get: 'nope', set: () => {}, del: () => {} };
    assert.throws(
      () => assertRedisClient(client, ['get', 'set', 'del'], trap),
      /WRAPPED: client is missing 'get\(\)'/,
    );
  });

  test('accepts a client with every required method', () => {
    const client = { get: () => {}, set: () => {}, del: () => {}, eval: () => {} };
    assert.doesNotThrow(() => assertRedisClient(client, ['get', 'set', 'del', 'eval'], trap));
  });

  test('empty method list still checks the shape', () => {
    assert.doesNotThrow(() => assertRedisClient({}, [], trap));
    assert.throws(() => assertRedisClient(null, [], trap));
  });
});
