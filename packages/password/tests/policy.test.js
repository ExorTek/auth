import { test } from 'node:test';
import assert from 'node:assert/strict';
import { policy, assertPolicy } from '../src/policy.js';
import { PasswordError, ErrorCode } from '../src/errors.js';

test('policy: default rule (minLength=12) — pass', () => {
  const r = policy('SomeReasonableP@ss1');
  assert.equal(r.valid, true);
  assert.deepEqual(r.violations, []);
});

test('policy: too-short flagged', () => {
  const r = policy('short');
  assert.equal(r.valid, false);
  assert.ok(r.violations.includes('too-short'));
});

test('policy: too-long flagged', () => {
  const r = policy('a'.repeat(2000));
  assert.ok(r.violations.includes('too-long'));
});

test('policy: requireClasses', () => {
  const r = policy('onlylowercase', { requireClasses: ['upper'] });
  assert.ok(r.violations.includes('missing-class'));
});

test('policy: denyList substring', () => {
  const r = policy('acme-company-pass1', { denyList: ['acme'] });
  assert.ok(r.violations.includes('in-deny-list'));
});

test('policy: userInfo substring', () => {
  const r = policy('bob-morning-1234', { userInfo: ['bob'] });
  assert.ok(r.violations.includes('contains-user-info'));
});

test('policy: requireMinScore calls strength() and populates result.strength', () => {
  const r = policy('aa', { requireMinScore: 3 });
  assert.ok(r.violations.includes('below-min-strength'));
  assert.ok(r.strength);
  assert.equal(typeof r.strength.score, 'number');
});

test('policy: requireMinScore not set → no strength probe', () => {
  const r = policy('good enough password 12');
  assert.equal(r.strength, undefined);
});

test('policy: non-string input → invalid', () => {
  const r = policy(42);
  assert.equal(r.valid, false);
});

test('assertPolicy: throws with details on violation', () => {
  assert.throws(
    () => assertPolicy('short'),
    err =>
      err instanceof PasswordError &&
      err.code === ErrorCode.POLICY_VIOLATION &&
      Array.isArray(err.details?.violations) &&
      err.details.violations.includes('too-short'),
  );
});

test('assertPolicy: passes silently on valid password', () => {
  assert.doesNotThrow(() => assertPolicy('SomeReasonableP@ss1'));
});
