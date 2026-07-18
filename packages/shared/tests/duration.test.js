import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parseDuration } from '../src/time/duration.js';

test('bare number is milliseconds (Node standard)', () => {
  assert.equal(parseDuration(0), 0);
  assert.equal(parseDuration(1), 1);
  assert.equal(parseDuration(900), 900);
  assert.equal(parseDuration(60_000), 60_000);
});

test('duration strings — short forms', () => {
  assert.equal(parseDuration('500ms'), 500);
  assert.equal(parseDuration('30s'), 30_000);
  assert.equal(parseDuration('15m'), 900_000);
  assert.equal(parseDuration('2h'), 7_200_000);
  assert.equal(parseDuration('7d'), 604_800_000);
  assert.equal(parseDuration('1w'), 604_800_000);
  assert.equal(parseDuration('1y'), 31_536_000_000);
  assert.equal(parseDuration('2yr'), 63_072_000_000);
});

test('duration strings — long / plural forms', () => {
  assert.equal(parseDuration('1 hour'), 3_600_000);
  assert.equal(parseDuration('2 hours'), 7_200_000);
  assert.equal(parseDuration('30 minutes'), 1_800_000);
  assert.equal(parseDuration('1 day'), 86_400_000);
  assert.equal(parseDuration('2 weeks'), 1_209_600_000);
  assert.equal(parseDuration('500 milliseconds'), 500);
});

test('duration strings — whitespace tolerated', () => {
  assert.equal(parseDuration('  15m  '), 900_000);
  assert.equal(parseDuration('15 m'), 900_000);
});

test('duration strings — fractional values', () => {
  assert.equal(parseDuration('1.5h'), 5_400_000);
  assert.equal(parseDuration('0.5s'), 500);
});

test('unit-less string defaults to milliseconds (matches bare-number branch)', () => {
  assert.equal(parseDuration('900'), 900);
  assert.equal(parseDuration('60000'), 60_000);
});

test('rejects non-finite numbers', () => {
  assert.throws(() => parseDuration(NaN), /finite/);
  assert.throws(() => parseDuration(Infinity), /finite/);
});

test('rejects unknown units', () => {
  assert.throws(() => parseDuration('5xyz'), /unknown time unit/);
});

test('rejects malformed strings', () => {
  assert.throws(() => parseDuration('abc'), /could not parse/);
  assert.throws(() => parseDuration(''), /could not parse/);
});

test('rejects non-string non-number inputs', () => {
  assert.throws(() => parseDuration(null), TypeError);
  assert.throws(() => parseDuration({}), TypeError);
  assert.throws(() => parseDuration([]), TypeError);
});
