import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { generate } from '../src/token.js';
import { OpaqueError, ErrorCode } from '../src/errors.js';

describe('generate', () => {
  test('bare generator formats', () => {
    assert.equal(generate({ format: 'hex', bytes: 16 }).length, 32);
    assert.match(generate({ format: 'base64url', bytes: 16 }), /^[A-Za-z0-9_-]+$/);
    assert.match(generate({ format: 'base58' }), /^[1-9A-HJ-NP-Za-km-z]+$/);
    assert.match(generate({ format: 'crockford', bytes: 10 }), /^[0-9A-HJKMNP-TV-Z]+$/);
    assert.match(generate({ format: 'ulid' }), /^[0-9A-Z]{26}$/);
    assert.match(generate({ format: 'uuid4' }), /^[0-9a-f-]{36}$/);
    assert.match(generate({ format: 'uuid7' }), /^[0-9a-f-]{36}$/);
    assert.equal(generate({ format: 'alphanumeric', length: 24 }).length, 24);
  });

  test('alphanumeric falls back to bytes when length omitted', () => {
    assert.equal(generate({ format: 'alphanumeric', bytes: 10 }).length, 10);
  });

  test('prefixed format defaults to hex generator', () => {
    const token = generate({ format: 'prefixed', prefix: 'usr' });
    assert.match(token, /^usr_[0-9a-f]{64}$/);
  });

  test('prefixed format with explicit generator and separator', () => {
    const token = generate({ format: 'prefixed', prefix: 'usr', generator: 'ulid', separator: '.' });
    assert.match(token, /^usr\.[0-9A-Z]{26}$/);
  });

  test('structured format', () => {
    const token = generate({ format: 'structured', version: 'v1', type: 'ref', generator: 'ulid', separator: '.' });
    assert.match(token, /^v1\.ref\.[0-9A-Z]{26}$/);
  });

  test('structured requires version and type', () => {
    assert.throws(() => generate({ format: 'structured', type: 'ref' }), OpaqueError);
    assert.throws(() => generate({ format: 'structured', version: 'v1' }), OpaqueError);
  });

  test('prefixed requires prefix', () => {
    assert.throws(
      () => generate({ format: 'prefixed' }),
      err => err instanceof OpaqueError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });

  test('throws on unsupported format', () => {
    assert.throws(
      () => generate({ format: 'nope' }),
      err => err instanceof OpaqueError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });

  test('throws on unsupported generator for prefixed', () => {
    assert.throws(() => generate({ format: 'prefixed', prefix: 'usr', generator: 'nope' }), OpaqueError);
  });

  test('throws on non-positive bytes', () => {
    assert.throws(() => generate({ format: 'hex', bytes: 0 }), OpaqueError);
    assert.throws(() => generate({ format: 'hex', bytes: -1 }), OpaqueError);
  });

  test('throws without options', () => {
    assert.throws(() => generate(), OpaqueError);
  });
});
