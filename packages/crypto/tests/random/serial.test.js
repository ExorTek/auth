import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { serial } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

const BLOCK_RE = /^[A-Z0-9]+$/;

describe('serial', () => {
  it('defaults to two 4-char uppercase-alphanumeric blocks joined by "-"', () => {
    const s = serial();
    assert.match(s, /^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
  });

  it('honors the prefix option', () => {
    const s = serial({ prefix: 'INV' });
    assert.ok(s.startsWith('INV-'));
    const parts = s.split('-');
    assert.equal(parts[0], 'INV');
    assert.equal(parts.length, 3); // prefix + 2 blocks
  });

  it('inserts the current calendar year when requested', () => {
    const year = new Date().getFullYear();
    const s = serial({ prefix: 'INV', year: true });
    const parts = s.split('-');
    assert.equal(parts[0], 'INV');
    assert.equal(parts[1], String(year));
    assert.equal(parts.length, 4); // prefix + year + 2 blocks
  });

  it('accepts custom block count and block length', () => {
    const s = serial({ prefix: 'ORD', blocks: 3, blockLen: 6 });
    const parts = s.split('-');
    assert.equal(parts[0], 'ORD');
    assert.equal(parts.length, 4);
    for (const block of parts.slice(1)) {
      assert.equal(block.length, 6);
      assert.match(block, BLOCK_RE);
    }
  });

  it('honors a custom separator', () => {
    const s = serial({ prefix: 'ORDER', separator: '.' });
    assert.ok(s.startsWith('ORDER.'));
    assert.ok(!s.includes('-'));
  });

  it('emits only uppercase A-Z and 0-9 in random blocks', () => {
    for (let i = 0; i < 200; i++) {
      const parts = serial({ blocks: 4, blockLen: 8 }).split('-');
      for (const block of parts) {
        assert.match(block, BLOCK_RE);
      }
    }
  });

  it('produces unique values across many draws', () => {
    const set = new Set(Array.from({ length: 5000 }, () => serial({ blocks: 2, blockLen: 4 })));
    assert.ok(set.size > 4990, `expected near-unique draws, got ${set.size}`);
  });

  it('rejects non-object options', () => {
    assert.throws(() => serial('bad'), (err) => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT);
    assert.throws(() => serial(null), (err) => err instanceof CryptoError);
    assert.throws(() => serial([]), (err) => err instanceof CryptoError);
  });

  it('rejects non-string prefix', () => {
    assert.throws(() => serial({ prefix: 123 }), (err) => err instanceof CryptoError);
  });

  it('rejects non-positive blocks or blockLen', () => {
    assert.throws(() => serial({ blocks: 0 }), (err) => err instanceof CryptoError);
    assert.throws(() => serial({ blockLen: 0 }), (err) => err instanceof CryptoError);
    assert.throws(() => serial({ blocks: -1 }), (err) => err instanceof CryptoError);
    assert.throws(() => serial({ blockLen: 1.5 }), (err) => err instanceof CryptoError);
  });

  it('rejects non-string separator', () => {
    assert.throws(() => serial({ separator: 42 }), (err) => err instanceof CryptoError);
  });
});
