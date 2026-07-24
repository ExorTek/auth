import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SessionError, ErrorCode } from '../src/errors.js';

test('SessionError carries code + message + status', () => {
  const err = new SessionError(ErrorCode.INVALID_TOKEN, 'nope');
  assert.equal(err.code, ErrorCode.INVALID_TOKEN);
  assert.equal(err.message, 'nope');
  assert.equal(err.name, 'SessionError');
  assert.equal(err.status, 401);
  assert.ok(err instanceof Error);
});

test('SessionError.status defaults per code', () => {
  assert.equal(new SessionError(ErrorCode.INVALID_ARGUMENT, '').status, 400);
  assert.equal(new SessionError(ErrorCode.EXPIRED, '').status, 401);
  assert.equal(new SessionError(ErrorCode.SESSION_NOT_FOUND, '').status, 401);
});

test('SessionError.status overridable', () => {
  const err = new SessionError(ErrorCode.INVALID_TOKEN, '', { status: 418 });
  assert.equal(err.status, 418);
});

test('SessionError carries details', () => {
  const err = new SessionError(ErrorCode.INVALID_TOKEN, '', {
    details: { userId: '42', limit: 3 },
  });
  assert.deepEqual(err.details, { userId: '42', limit: 3 });
});

test('ErrorCode is frozen', () => {
  assert.throws(() => {
    ErrorCode.NEW_ONE = 'x';
  });
});
