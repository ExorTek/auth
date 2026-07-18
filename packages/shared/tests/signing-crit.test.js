import { test } from 'node:test';
import assert from 'node:assert/strict';

import { assertSignSide, assertVerifySide } from '../src/signing/crit.js';

test('sign: undefined crit passes', () => {
  assertSignSide(undefined, {});
});

test('sign: every name must be present as a header member', () => {
  assertSignSide(['b64'], { b64: false });
  assert.throws(() => assertSignSide(['b64'], {}), /no such member/);
});

test('sign: empty array rejected', () => {
  assert.throws(() => assertSignSide([], {}), /empty array/);
});

test('sign: non-array rejected', () => {
  assert.throws(() => assertSignSide('b64', {}), /array of strings/);
});

test('sign: crit cannot list itself', () => {
  assert.throws(() => assertSignSide(['crit'], { crit: 1 }), /list itself/);
});

test('sign: duplicates rejected', () => {
  assert.throws(() => assertSignSide(['b64', 'b64'], { b64: false }), /duplicate/);
});

test('sign: non-string entry rejected', () => {
  assert.throws(() => assertSignSide([42], { 42: true }), /non-string entry/);
});

test('verify: known param passes', () => {
  const known = new Set(['b64']);
  assertVerifySide(['b64'], { b64: false }, known);
});

test('verify: unknown critical param throws with critName attached', () => {
  const known = new Set([]);
  try {
    assertVerifySide(['x-custom'], { 'x-custom': true }, known);
    assert.fail('should throw');
  } catch (err) {
    assert.match(err.message, /does not understand/);
    assert.equal(err.critName, 'x-custom');
  }
});

test('verify: extraKnown opt-in works', () => {
  const known = new Set([]);
  const extraKnown = ['x-app'];
  assertVerifySide(['x-app'], { 'x-app': true }, known, extraKnown);
});

test('verify: name must also be a header member', () => {
  const known = new Set(['b64']);
  assert.throws(() => assertVerifySide(['b64'], {}, known), /no such member/);
});

test('verify: undefined crit passes', () => {
  assertVerifySide(undefined, {}, new Set(['b64']));
});
