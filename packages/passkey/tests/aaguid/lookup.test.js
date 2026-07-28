import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { lookup, table } from '../../src/aaguid.js';

const TABLE_SOURCE = fileURLToPath(new URL('../../data/aaguid-table.js', import.meta.url));

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

  test('source file has no duplicate AAGUID keys', () => {
    // Reading the source text catches duplicates that object-literal
    // semantics would otherwise silently collapse to a single entry.
    const src = readFileSync(TABLE_SOURCE, 'utf8');
    const keys = Array.from(src.matchAll(/'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'\s*:/gi)).map(
      m => m[1].toLowerCase(),
    );
    assert.ok(keys.length > 0, 'no AAGUID keys parsed from source');
    const seen = new Set();
    const dupes = [];
    for (const k of keys) {
      if (seen.has(k)) {
        dupes.push(k);
      }
      seen.add(k);
    }
    assert.deepEqual(dupes, [], `duplicate AAGUID key(s) in source: ${dupes.join(', ')}`);
  });
});
