import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PasswordError, ErrorCode } from '../src/errors.js';

test('PasswordError carries code + message', () => {
  const err = new PasswordError(ErrorCode.INVALID_ARGUMENT, 'nope');
  assert.equal(err.code, ErrorCode.INVALID_ARGUMENT);
  assert.equal(err.message, 'nope');
  assert.equal(err.name, 'PasswordError');
  assert.ok(err instanceof Error);
});

test('PasswordError.status defaults from code', () => {
  assert.equal(new PasswordError(ErrorCode.INVALID_ARGUMENT, '').status, 400);
  assert.equal(new PasswordError(ErrorCode.INVALID_PASSWORD, '').status, 401);
  assert.equal(new PasswordError(ErrorCode.MISSING_PEER_DEP, '').status, 500);
  assert.equal(new PasswordError(ErrorCode.BREACHED_PASSWORD, '').status, 422);
});

test('PasswordError.status can be overridden', () => {
  const err = new PasswordError(ErrorCode.INVALID_ARGUMENT, '', { status: 418 });
  assert.equal(err.status, 418);
});

test('PasswordError carries structured details', () => {
  const err = new PasswordError(ErrorCode.POLICY_VIOLATION, '', {
    details: { violations: ['too-short'] },
  });
  assert.deepEqual(err.details, { violations: ['too-short'] });
});

test('ErrorCode is frozen', () => {
  assert.throws(() => {
    ErrorCode.NEW_CODE = 'NEW_CODE';
  });
});
