import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { BaseError } from '../src/errors.js';

class DemoError extends BaseError {
  static statuses = { BAD: 400, DENIED: 403 };
  static defaultStatus = 401;
}

class PlainError extends BaseError {}

describe('BaseError', () => {
  it('subclass instances carry name, code, message', () => {
    const err = new DemoError('BAD', 'nope');
    assert.ok(err instanceof DemoError);
    assert.ok(err instanceof BaseError);
    assert.ok(err instanceof Error);
    assert.equal(err.name, 'DemoError');
    assert.equal(err.code, 'BAD');
    assert.equal(err.message, 'nope');
  });

  it('derives status from static statuses with defaultStatus fallback', () => {
    assert.equal(new DemoError('BAD', 'x').status, 400);
    assert.equal(new DemoError('DENIED', 'x').status, 403);
    assert.equal(new DemoError('UNKNOWN', 'x').status, 401);
  });

  it('honors an explicit status override', () => {
    assert.equal(new DemoError('BAD', 'x', { status: 422 }).status, 422);
  });

  it('carries no status when the subclass declares no statuses', () => {
    const err = new PlainError('BAD', 'x');
    assert.equal('status' in err, false);
    assert.equal(new PlainError('BAD', 'x', { status: 418 }).status, 418);
  });

  it('preserves cause and attaches details only when provided', () => {
    const cause = new Error('root');
    const err = new DemoError('BAD', 'x', { cause, details: { field: 'iss' } });
    assert.equal(err.cause, cause);
    assert.deepEqual(err.details, { field: 'iss' });
    assert.equal('details' in new DemoError('BAD', 'x'), false);
    assert.equal('cause' in new DemoError('BAD', 'x'), false);
  });

  it('keeps distinct subclass identities', () => {
    assert.ok(!(new DemoError('BAD', 'x') instanceof PlainError));
  });
});
