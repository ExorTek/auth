import { test } from 'node:test';
import assert from 'node:assert/strict';
import { strength } from '../src/strength.js';

test('empty / non-string → score 0', () => {
  assert.equal(strength('').score, 0);
  assert.equal(strength(null).score, 0);
  assert.equal(strength(42).score, 0);
});

test('short single-class → low score', () => {
  const r = strength('abc');
  assert.equal(r.score, 0);
  assert.ok(r.weaknesses.includes('too-short'));
  assert.ok(r.weaknesses.includes('single-class'));
});

test('single-class 12 chars → still flagged', () => {
  const r = strength('abcdefghijkl');
  assert.ok(r.weaknesses.includes('single-class'));
  assert.ok(r.weaknesses.includes('sequential'));
});

test('mixed-class high-entropy → high score', () => {
  const r = strength('Kj9#mLp$vXn2!wQeR8@zY4');
  assert.ok(r.score >= 3, `expected ≥ 3, got ${r.score}`);
  assert.ok(!r.weaknesses.includes('single-class'));
});

test('repetition detected', () => {
  const r = strength('aaaaBcdE1!');
  assert.ok(r.weaknesses.includes('repetition'));
});

test('sequential ascending run detected', () => {
  const r = strength('abcd1234!!');
  assert.ok(r.weaknesses.includes('sequential'));
});

test('sequential descending run detected', () => {
  const r = strength('9876wxyz!!');
  assert.ok(r.weaknesses.includes('sequential'));
});

test('userInfo substring flagged', () => {
  const r = strength('myEmail1234!', { userInfo: ['email'] });
  assert.ok(r.weaknesses.includes('contains-user-info'));
});

test('userInfo substring < 3 chars ignored', () => {
  const r = strength('ab!Correct1', { userInfo: ['a', 'ab'] });
  assert.ok(!r.weaknesses.includes('contains-user-info'));
});

test('entropyBits is a number', () => {
  const r = strength('SomeReasonableP@ss1');
  assert.equal(typeof r.entropyBits, 'number');
  assert.ok(r.entropyBits > 0);
});

test('lengthAfterNormalize is NFKC length', () => {
  // 'ﬁ' (U+FB01, ligature) NFKC → 'fi' (2 chars)
  const r = strength('paﬁ' + 'xxxxxxxx');
  assert.equal(r.lengthAfterNormalize, 12);
});
