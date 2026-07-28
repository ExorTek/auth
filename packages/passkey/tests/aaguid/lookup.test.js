import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { lookup, table } from '../../src/aaguid.js';

describe('aaguid lookup', () => {
  test('returns the entry for a known AAGUID', () => {
    const entry = lookup('ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4');
    assert.ok(entry);
    assert.match(entry.name, /Google Password Manager/);
  });

  test('returns null for unknown AAGUID', () => {
    assert.equal(lookup('00000000-0000-0000-0000-000000000000'), null);
  });

  test('table is a plain object and non-empty', () => {
    assert.ok(typeof table === 'object' && table !== null);
    assert.ok(Object.keys(table).length > 0);
  });

  test('every entry has a name string', () => {
    for (const [aaguid, entry] of Object.entries(table)) {
      assert.equal(typeof entry.name, 'string', `${aaguid} missing name`);
      assert.ok(entry.name.length > 0, `${aaguid} has empty name`);
    }
  });
});
