import { test } from 'node:test';
import assert from 'node:assert/strict';
import { backupCodes, normalizeBackupCode, compareBackupCode, OtpError } from '../src/index.js';

test('backupCodes: default 10 codes, dash-grouped', () => {
  const codes = backupCodes();
  assert.equal(codes.length, 10);
  // Each code is a dash-separated string with the raw length of 10.
  for (const c of codes) {
    assert.equal(c.replace(/-/g, '').length, 10);
    assert.match(c, /^[0-9A-Z]+(-[0-9A-Z]+)+$/);
  }
});

test('backupCodes: unambiguous alphabet (Crockford — no 0/O/1/I/L)', () => {
  const codes = backupCodes(100);
  const raw = codes.join('').replace(/-/g, '');
  // Explicitly forbidden characters:
  assert.doesNotMatch(raw, /[OILU]/);
});

test('backupCodes: all unique in a batch', () => {
  const codes = backupCodes(50);
  const set = new Set(codes);
  assert.equal(set.size, codes.length);
});

test('backupCodes: single group with groups: 1', () => {
  const codes = backupCodes(5, { groups: 1 });
  for (const c of codes) {
    assert.doesNotMatch(c, /-/);
  }
});

test('backupCodes: custom length + groups', () => {
  const codes = backupCodes(3, { length: 12, groups: 3 });
  for (const c of codes) {
    assert.equal(c.replace(/-/g, '').length, 12);
    assert.equal(c.split('-').length, 3);
  }
});

test('backupCodes: rejects out-of-range args', () => {
  assert.throws(() => backupCodes(0), OtpError);
  assert.throws(() => backupCodes(200), OtpError);
  assert.throws(() => backupCodes(10, { length: 3 }), OtpError);
  assert.throws(() => backupCodes(10, { groups: 20, length: 10 }), OtpError);
});

test('normalizeBackupCode: strips whitespace / dashes / lower-case', () => {
  assert.equal(normalizeBackupCode('abcd-1234'), 'ABCD1234');
  assert.equal(normalizeBackupCode(' AbCd 12 34 '), 'ABCD1234');
  assert.equal(normalizeBackupCode(''), '');
  assert.equal(normalizeBackupCode(null), '');
});

test('compareBackupCode: user paste vs stored — timing-safe match', () => {
  const [stored] = backupCodes(1);
  // User pastes with different case + spaces.
  const pasteStyle = stored.toLowerCase().replace(/-/g, ' ');
  assert.equal(compareBackupCode(pasteStyle, stored), true);
});

test('compareBackupCode: rejects mismatch without throwing', () => {
  const [a] = backupCodes(1);
  assert.equal(compareBackupCode('WRONG-CODE', a), false);
  assert.equal(compareBackupCode('', a), false);
  assert.equal(compareBackupCode(null, a), false);
});

// Preset shapes

import { backupPresets } from '../src/index.js';

test('backupPresets.numeric: Google-style 4-4 digits', () => {
  const codes = backupCodes(5, backupPresets.numeric);
  for (const c of codes) {
    assert.match(c, /^\d{4}-\d{4}$/);
  }
});

test('backupPresets.long: 12 unambiguous chars in 3 groups', () => {
  const codes = backupCodes(3, backupPresets.long);
  for (const c of codes) {
    assert.equal(c.replace(/-/g, '').length, 12);
    assert.equal(c.split('-').length, 3);
    assert.doesNotMatch(c, /[OILU]/);
  }
});

test('backupPresets.hex: 8 hex chars, 2 groups', () => {
  const codes = backupCodes(3, backupPresets.hex);
  for (const c of codes) {
    assert.match(c, /^[0-9A-F]{4}-[0-9A-F]{4}$/);
  }
});

test('backupPresets.short: 6 chars ungrouped', () => {
  const codes = backupCodes(3, backupPresets.short);
  for (const c of codes) {
    assert.equal(c.length, 6);
    assert.doesNotMatch(c, /-/);
    assert.doesNotMatch(c, /[OILU]/);
  }
});

test('backupPresets: spread + override composes cleanly', () => {
  const codes = backupCodes(3, { ...backupPresets.numeric, groups: 4 });
  for (const c of codes) {
    assert.equal(c.replace(/-/g, '').length, 8);
    assert.equal(c.split('-').length, 4);
  }
});
