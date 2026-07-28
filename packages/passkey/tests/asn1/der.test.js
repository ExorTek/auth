import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { TAG, contextTag, readTlv, intoSequence, decodeOid, encodeOid, findExtension } from '../../src/asn1/der.js';

/**
 * Assemble one TLV. Uses short-form length when the payload fits,
 * long-form otherwise. Enough for tests — the DER walker itself is
 * the code under test, and this fixture builder must not depend on
 * it.
 */
function tlv(tag, contents) {
  const body = contents instanceof Uint8Array ? contents : new Uint8Array(contents);
  const len = body.byteLength;
  let header;
  if (len < 0x80) {
    header = [tag, len];
  } else if (len <= 0xff) {
    header = [tag, 0x81, len];
  } else if (len <= 0xffff) {
    header = [tag, 0x82, (len >> 8) & 0xff, len & 0xff];
  } else {
    header = [tag, 0x83, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff];
  }
  const out = new Uint8Array(header.length + len);
  out.set(header, 0);
  out.set(body, header.length);
  return out;
}

function concat(...chunks) {
  const total = chunks.reduce((n, c) => n + c.byteLength, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.byteLength;
  }
  return out;
}

function h(hex) {
  const clean = hex.replace(/\s+/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

describe('DER — readTlv basic shapes', () => {
  test('short-form length', () => {
    const t = readTlv(h('0403aabbcc'));
    assert.equal(t.tag, TAG.OCTET_STRING);
    assert.deepEqual(t.contents, new Uint8Array([0xaa, 0xbb, 0xcc]));
    assert.equal(t.totalLength, 5);
  });

  test('long-form length, 1 byte', () => {
    const contents = new Uint8Array(200).fill(0xff);
    const bytes = tlv(TAG.OCTET_STRING, contents);
    const t = readTlv(bytes);
    assert.equal(t.contents.byteLength, 200);
    assert.equal(t.totalLength, 200 + 3);
  });

  test('long-form length, 2 bytes', () => {
    const contents = new Uint8Array(500).fill(0xaa);
    const bytes = tlv(TAG.OCTET_STRING, contents);
    const t = readTlv(bytes);
    assert.equal(t.contents.byteLength, 500);
    assert.equal(t.totalLength, 500 + 4);
  });

  test('reports tag class + constructed bit', () => {
    // SEQUENCE (0x30) — universal + constructed.
    const t = readTlv(tlv(TAG.SEQUENCE, new Uint8Array(0)));
    assert.equal(t.tagClass, 0);
    assert.equal(t.constructed, true);
    assert.equal(t.tagNumber, 0x10);
  });

  test('context tag [3] EXPLICIT (0xa3)', () => {
    const t = readTlv(tlv(contextTag(3), new Uint8Array([0x01])));
    assert.equal(t.tagClass, 2);
    assert.equal(t.constructed, true);
    assert.equal(t.tagNumber, 3);
  });
});

describe('DER — readTlv rejections', () => {
  test('rejects indefinite-length form', () => {
    assert.throws(() => readTlv(h('308000')), /indefinite length/);
  });

  test('rejects high-tag-number form', () => {
    assert.throws(() => readTlv(h('1f2000')), /high-tag-number/);
  });

  test('rejects truncated length', () => {
    assert.throws(() => readTlv(h('0482')), /truncated inside long-form length/);
  });

  test('rejects declared length beyond buffer', () => {
    assert.throws(() => readTlv(h('040500')), /only .+ available/);
  });

  test('rejects non-Uint8Array input', () => {
    assert.throws(() => readTlv([0x04, 0x00]), /Uint8Array/);
    assert.throws(() => readTlv('0400'), /Uint8Array/);
  });
});

describe('DER — readChildren + intoSequence', () => {
  test('walks a SEQUENCE of two OCTET STRINGs', () => {
    const inner = concat(tlv(TAG.OCTET_STRING, h('11')), tlv(TAG.OCTET_STRING, h('2233')));
    const outer = tlv(TAG.SEQUENCE, inner);
    const kids = intoSequence(outer);
    assert.equal(kids.length, 2);
    assert.deepEqual(kids[0].contents, h('11'));
    assert.deepEqual(kids[1].contents, h('2233'));
  });

  test('intoSequence rejects a wrong outer tag', () => {
    assert.throws(() => intoSequence(tlv(TAG.OCTET_STRING, h('11'))), /expected tag 0x30/);
  });
});

describe('DER — OID encode / decode round-trip', () => {
  for (const oid of [
    '1.2.840.113549.1.1.1', // rsaEncryption
    '1.2.840.10045.2.1', // ecPublicKey
    '1.2.840.10045.3.1.7', // prime256v1 / P-256
    '2.5.29.15', // keyUsage
    '2.5.29.17', // subjectAltName
    '2.5.29.19', // basicConstraints
    '2.5.29.37', // extKeyUsage
    '1.3.6.1.4.1.45724.1.1.4', // FIDO AAGUID
    '1.2.840.113635.100.8.2', // Apple attestation nonce
    '1.3.6.1.4.1.11129.2.1.17', // Android key attestation
    '2.23.133.8.3', // TCG-KP-AIK
  ]) {
    test(`round-trips ${oid}`, () => {
      const encoded = encodeOid(oid);
      const decoded = decodeOid(encoded);
      assert.equal(decoded, oid);
    });
  }

  test('AAGUID OID encodes to the RFC-shaped byte sequence', () => {
    // 1.3.6.1.4.1.45724.1.1.4
    //  → head:      40*1+3 = 43 = 0x2b
    //  → 6/1/4/1:   0x06 0x01 0x04 0x01
    //  → 45724:     base-128 = 2, 101, 92 with continuation bits = 0x82 0xe5 0x1c
    //  → 1/1/4:     0x01 0x01 0x04
    assert.deepEqual(encodeOid('1.3.6.1.4.1.45724.1.1.4'), h('2b0601040182e51c010104'));
  });

  test('rejects non-minimal encoding (leading 0x80)', () => {
    // Two-byte subid `80 02` decodes to 2 but is padded — DER forbids it.
    assert.throws(() => decodeOid(new Uint8Array([0x2b, 0x80, 0x02])), /non-minimal/);
  });

  test('rejects truncated OID (continuation bit on last byte)', () => {
    assert.throws(() => decodeOid(new Uint8Array([0x2b, 0x82])), /truncated/);
  });

  test('rejects empty OID contents', () => {
    assert.throws(() => decodeOid(new Uint8Array(0)), /non-empty/);
  });
});

describe('DER — findExtension', () => {
  /**
   * Build a minimal certificate-shaped DER envelope: SEQUENCE
   * containing SEQUENCE (TBSCertificate) containing exactly one
   * child — a `[3] EXPLICIT Extensions` block with the extensions
   * we care about. We skip every field the walker doesn't need to
   * look at (`findExtension` seeks the `[3]` context tag directly).
   */
  function buildCertWithExtensions(extensions) {
    const extsSeq = tlv(TAG.SEQUENCE, concat(...extensions));
    const extsExplicit = tlv(contextTag(3), extsSeq);
    const tbs = tlv(TAG.SEQUENCE, extsExplicit);
    return tlv(TAG.SEQUENCE, tbs);
  }

  /**
   * Build a single Extension TLV — `SEQUENCE { OID [, BOOLEAN
   * critical] , OCTET STRING extnValue }`.
   */
  function extension(oid, extnValue, { critical = false } = {}) {
    const parts = [tlv(TAG.OBJECT_IDENTIFIER, encodeOid(oid))];
    if (critical) {
      parts.push(tlv(TAG.BOOLEAN, new Uint8Array([0xff])));
    }
    parts.push(tlv(TAG.OCTET_STRING, extnValue));
    return tlv(TAG.SEQUENCE, concat(...parts));
  }

  test('locates a FIDO AAGUID extension and returns its extnValue', () => {
    // Real AAGUID extension: extnValue is OCTET STRING wrapping OCTET
    // STRING wrapping the 16-byte AAGUID.
    const aaguid = h('00112233445566778899aabbccddeeff');
    const inner = tlv(TAG.OCTET_STRING, aaguid);
    const cert = buildCertWithExtensions([extension('1.3.6.1.4.1.45724.1.1.4', inner)]);

    const extnValue = findExtension(cert, '1.3.6.1.4.1.45724.1.1.4');
    assert.ok(extnValue);
    // The returned bytes are the outer OCTET STRING's contents —
    // the inner OCTET STRING TLV. Unwrap once and check.
    const innerTlv = readTlv(extnValue);
    assert.equal(innerTlv.tag, TAG.OCTET_STRING);
    assert.deepEqual(innerTlv.contents, aaguid);
  });

  test('locates an Apple attestation nonce extension', () => {
    const nonce = h('deadbeefcafeface');
    const cert = buildCertWithExtensions([extension('1.2.840.113635.100.8.2', nonce)]);
    const extnValue = findExtension(cert, '1.2.840.113635.100.8.2');
    assert.deepEqual(extnValue, nonce);
  });

  test('handles the optional critical BOOLEAN before extnValue', () => {
    const payload = h('112233');
    const cert = buildCertWithExtensions([extension('2.5.29.19', payload, { critical: true })]);
    const extnValue = findExtension(cert, '2.5.29.19');
    assert.deepEqual(extnValue, payload);
  });

  test('returns null when the extension is absent', () => {
    const cert = buildCertWithExtensions([extension('2.5.29.19', h('01'))]);
    assert.equal(findExtension(cert, '1.3.6.1.4.1.45724.1.1.4'), null);
  });

  test('returns null when the cert has no extensions block', () => {
    // TBSCertificate SEQUENCE with a single dummy OCTET STRING and
    // no [3] context tag.
    const tbs = tlv(TAG.SEQUENCE, tlv(TAG.OCTET_STRING, h('00')));
    const cert = tlv(TAG.SEQUENCE, tbs);
    assert.equal(findExtension(cert, '1.3.6.1.4.1.45724.1.1.4'), null);
  });

  test('walks past an unrelated extension to find the requested one', () => {
    const cert = buildCertWithExtensions([
      extension('2.5.29.19', h('01')),
      extension('2.5.29.15', h('02')),
      extension('1.3.6.1.4.1.45724.1.1.4', h('deadbeef')),
    ]);
    assert.deepEqual(findExtension(cert, '1.3.6.1.4.1.45724.1.1.4'), h('deadbeef'));
  });
});

describe('DER — contextTag argument guard', () => {
  test('rejects out-of-range', () => {
    assert.throws(() => contextTag(-1), /out of range/);
    assert.throws(() => contextTag(31), /out of range/);
  });
});
