import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { decode, decodeWithLength } from '../../src/cbor/decode.js';

/**
 * @param {string} hex
 */
function h(hex) {
  const clean = hex.replace(/\s+/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

describe('CBOR — RFC 8949 Appendix A unsigned/negative integers', () => {
  for (const [hex, expected] of [
    ['00', 0],
    ['01', 1],
    ['0a', 10],
    ['17', 23],
    ['1818', 24],
    ['1819', 25],
    ['1864', 100],
    ['1903e8', 1000],
    ['1a000f4240', 1_000_000],
    ['1b000000e8d4a51000', 1_000_000_000_000],
    ['20', -1],
    ['29', -10],
    ['3863', -100],
    ['3903e7', -1000],
  ]) {
    test(`decode(0x${hex}) === ${expected}`, () => {
      assert.strictEqual(decode(h(hex)), expected);
    });
  }

  test('decodes u64 above Number.MAX_SAFE_INTEGER as bigint', () => {
    // 2^53 + 1 = 9_007_199_254_740_993 — one past the safe integer.
    assert.strictEqual(decode(h('1b0020000000000001')), 9_007_199_254_740_993n);
  });

  test('decodes negative int below Number.MIN_SAFE_INTEGER as bigint', () => {
    assert.strictEqual(decode(h('3b0020000000000000')), -9_007_199_254_740_993n);
  });
});

describe('CBOR — RFC 8949 Appendix A byte + text strings', () => {
  test("decode(0x40) === h''", () => {
    assert.deepStrictEqual(decode(h('40')), new Uint8Array(0));
  });

  test("decode(0x4401020304) === h'01020304'", () => {
    assert.deepStrictEqual(decode(h('4401020304')), new Uint8Array([1, 2, 3, 4]));
  });

  test('decode(0x60) === ""', () => {
    assert.strictEqual(decode(h('60')), '');
  });

  test('decode(0x6161) === "a"', () => {
    assert.strictEqual(decode(h('6161')), 'a');
  });

  test('decode(0x6449455446) === "IETF"', () => {
    assert.strictEqual(decode(h('6449455446')), 'IETF');
  });

  test('text string with invalid UTF-8 throws', () => {
    // 0x61 = 1-byte text; 0xff is never a legal UTF-8 continuation.
    assert.throws(() => decode(h('61ff')));
  });
});

describe('CBOR — RFC 8949 Appendix A arrays + maps', () => {
  test('decode([]) → []', () => {
    assert.deepStrictEqual(decode(h('80')), []);
  });

  test('decode([1,2,3]) → [1,2,3]', () => {
    assert.deepStrictEqual(decode(h('83010203')), [1, 2, 3]);
  });

  test('decode({}) → empty Map', () => {
    const m = decode(h('a0'));
    assert.ok(m instanceof Map);
    assert.strictEqual(m.size, 0);
  });

  test('decode({1:2, 3:4}) → Map', () => {
    const m = decode(h('a201020304'));
    assert.strictEqual(m.get(1), 2);
    assert.strictEqual(m.get(3), 4);
    assert.strictEqual(m.size, 2);
  });

  test('decode({"a":1, "b":[2,3]}) → Map with mixed values', () => {
    const m = decode(h('a26161016162820203'));
    assert.strictEqual(m.get('a'), 1);
    assert.deepStrictEqual(m.get('b'), [2, 3]);
  });

  test('map with duplicate keys throws (strict decoder)', () => {
    assert.throws(() => decode(h('a201020103')), /duplicate map key/);
  });
});

describe('CBOR — simple values + floats', () => {
  test('false / true / null / undefined', () => {
    assert.strictEqual(decode(h('f4')), false);
    assert.strictEqual(decode(h('f5')), true);
    assert.strictEqual(decode(h('f6')), null);
    assert.strictEqual(decode(h('f7')), undefined);
  });

  test('half-precision 0.0', () => {
    assert.strictEqual(decode(h('f90000')), 0);
  });

  test('single-precision 100000.0', () => {
    assert.strictEqual(decode(h('fa47c35000')), 100000);
  });

  test('double-precision 1.1', () => {
    assert.strictEqual(decode(h('fb3ff199999999999a')), 1.1);
  });
});

describe('CBOR — rejections', () => {
  test('tags (major type 6) rejected', () => {
    // 0xc074 = tag 0 wrapping a 20-char text — legal CBOR, not for us.
    assert.throws(() => decode(h('c0743230313330332d32355432303a30343a30305a')), /tags/);
  });

  test('indefinite-length arrays rejected', () => {
    assert.throws(() => decode(h('9f018202039f0405ffff')), /indefinite-length/);
  });

  test('indefinite-length maps rejected', () => {
    assert.throws(() => decode(h('bf6346756ef563416d7421ff')), /indefinite-length/);
  });

  test('trailing bytes rejected', () => {
    assert.throws(() => decode(h('0100')), /trailing/);
  });

  test('truncated input rejected', () => {
    assert.throws(() => decode(h('44010203')), /unexpected end/);
  });

  test('non-Uint8Array input rejected', () => {
    assert.throws(() => decode([0x00]), /Uint8Array/);
    assert.throws(() => decode('00'), /Uint8Array/);
  });
});

describe('CBOR — WebAuthn-shaped structures', () => {
  test('attestation-object-ish outer map with fmt / authData / attStmt', () => {
    // { "fmt": "none", "authData": h'aabbcc', "attStmt": {} }
    const bytes = h('a363666d74646e6f6e656861757468446174614400aabbcc6761747453746d74a0');
    const outer = decode(bytes);
    assert.ok(outer instanceof Map);
    assert.strictEqual(outer.get('fmt'), 'none');
    assert.deepStrictEqual(outer.get('authData'), new Uint8Array([0x00, 0xaa, 0xbb, 0xcc]));
    assert.ok(outer.get('attStmt') instanceof Map);
    assert.strictEqual(outer.get('attStmt').size, 0);
  });

  test('COSE ES256 key: kty=2, alg=-7, crv=1, x, y — negative int keys survive', () => {
    // { 1: 2, 3: -7, -1: 1, -2: h'11'*32, -3: h'22'*32 }
    const key = h(
      'a5' +
        '01' +
        '02' +
        '03' +
        '26' +
        '20' +
        '01' +
        '21' +
        '5820' +
        '1111111111111111111111111111111111111111111111111111111111111111' +
        '22' +
        '5820' +
        '2222222222222222222222222222222222222222222222222222222222222222',
    );
    const m = decode(key);
    assert.strictEqual(m.get(1), 2);
    assert.strictEqual(m.get(3), -7);
    assert.strictEqual(m.get(-1), 1);
    assert.ok(m.get(-2) instanceof Uint8Array);
    assert.strictEqual(m.get(-2).byteLength, 32);
    assert.strictEqual(m.get(-3).byteLength, 32);
  });
});

describe('CBOR — decodeWithLength', () => {
  test('reports bytes read for the outer item, ignores trailing bytes', () => {
    // {} followed by two junk bytes.
    const buf = h('a0aabb');
    const { value, bytesRead } = decodeWithLength(buf);
    assert.ok(value instanceof Map);
    assert.strictEqual(bytesRead, 1);
  });
});

describe('cbor — recursion depth cap (DoS hardening)', () => {
  test('rejects deeply nested arrays past MAX_DEPTH', () => {
    // 40 single-element array heads (0x81) then a 0-value; each head
    // costs one byte but one stack frame — the classic cheap-DoS shape.
    const heads = new Uint8Array([...Array(40).fill(0x81), 0x00]);
    assert.throws(() => decode(heads), /nesting depth exceeds/);
  });

  test('accepts nesting within the cap', () => {
    // 8 nested arrays terminating in an integer — comfortably shallow.
    const ok = new Uint8Array([...Array(8).fill(0x81), 0x00]);
    const value = decode(ok);
    assert.ok(Array.isArray(value));
  });
});
