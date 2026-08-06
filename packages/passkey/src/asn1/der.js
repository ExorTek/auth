/**
 * Minimal DER walker — X.690 (BER/DER) restricted to the subset
 * WebAuthn needs.
 *
 * We don't reimplement ASN.1: we walk a byte stream, read tag /
 * length / value triples, decode OIDs, and expose enough
 * navigation (`intoSequence`, `findExtension`) for the
 * attestation-format handlers to pull out extension raw bytes by
 * OID. Reference: ITU-T X.690 §8, RFC 5280 §4.1 (Certificate
 * structure), X.680 §31 (OID encoding).
 *
 * Deliberately restrictive:
 *   - Indefinite-length form (0x80) is rejected. DER forbids it
 *     entirely; BER-only content has no place in a certificate.
 *   - High-tag-number form (tag byte low 5 bits = 0x1f) IS parsed —
 *     the Android Key attestation `AuthorizationList` uses Keymaster
 *     tag numbers well above 30 (e.g. `allApplications [600]`). For
 *     those TLVs `tag` is the sentinel first byte and the true number
 *     is in `tagNumber`; universal low-tag TLVs are unaffected.
 */

import { PasskeyError, ErrorCode } from '../errors.js';
import { isString } from '@exortek/shared/predicates';

// Universal tag constants (X.680 §8.6).
export const TAG = Object.freeze({
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OBJECT_IDENTIFIER: 0x06,
  UTF8_STRING: 0x0c,
  PRINTABLE_STRING: 0x13,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  SEQUENCE: 0x30,
  SET: 0x31,
});

/**
 * Build a context-specific constructed tag byte — `[n] EXPLICIT`
 * from RFC 5280.
 *
 * @param {number} n
 */
export function contextTag(n) {
  if (n < 0 || n > 30) {
    throw new PasskeyError(ErrorCode.DECODE_ERROR, `der: context tag ${n} out of range`);
  }
  return 0xa0 | n;
}

/**
 * A parsed TLV — `contents` is a view over the same buffer, no copy.
 *
 * @typedef {object} Tlv
 * @property {number} tag         The full tag byte, class + P/C + number.
 * @property {number} tagClass    Tag class 0..3 (universal/application/context/private).
 * @property {boolean} constructed  True for constructed encoding (P/C bit set).
 * @property {number} tagNumber   Bottom 5 bits of the tag byte.
 * @property {Uint8Array} contents  Bytes carried by this TLV (no tag, no length).
 * @property {number} totalLength  Total bytes consumed from the source, including tag + length.
 */

/**
 * Read one TLV starting at `offset` in `bytes`.
 *
 * @param {Uint8Array} bytes
 * @param {number} [offset=0]
 * @returns {Tlv}
 */
export function readTlv(bytes, offset = 0) {
  if (!(bytes instanceof Uint8Array)) {
    throw new PasskeyError(ErrorCode.DECODE_ERROR, 'der: expected Uint8Array');
  }
  if (offset < 0 || offset >= bytes.byteLength) {
    throw new PasskeyError(ErrorCode.DECODE_ERROR, `der: offset ${offset} out of range (len ${bytes.byteLength})`);
  }

  let pos = offset;
  const tag = bytes[pos++];
  const tagClass = (tag >> 6) & 0x03;
  const constructed = (tag & 0x20) !== 0;
  let tagNumber = tag & 0x1f;

  if (tagNumber === 0x1f) {
    // High-tag-number form: the real number is a base-128 big-endian
    // run, continuation bit set on every byte but the last.
    if (pos >= bytes.byteLength) {
      throw new PasskeyError(ErrorCode.DECODE_ERROR, 'der: truncated in high-tag-number form');
    }
    if ((bytes[pos] & 0x7f) === 0) {
      // A leading byte of 0x80 encodes a redundant zero — forbidden
      // (X.690 §8.1.2.4.2c), and 0x1f 0x00 would mean "use low form".
      throw new PasskeyError(ErrorCode.DECODE_ERROR, 'der: non-minimal high-tag-number encoding');
    }
    tagNumber = 0;
    let count = 0;
    let b;
    do {
      if (pos >= bytes.byteLength) {
        throw new PasskeyError(ErrorCode.DECODE_ERROR, 'der: truncated in high-tag-number form');
      }
      b = bytes[pos++];
      tagNumber = tagNumber * 128 + (b & 0x7f);
      count += 1;
      if (count > 4) {
        throw new PasskeyError(ErrorCode.DECODE_ERROR, 'der: high-tag-number too large');
      }
    } while ((b & 0x80) !== 0);
  }
  if (pos >= bytes.byteLength) {
    throw new PasskeyError(ErrorCode.DECODE_ERROR, 'der: truncated after tag');
  }

  // Length: short form if MSB clear (0..127), long form otherwise
  // (X.690 §8.1.3).
  const firstLen = bytes[pos++];
  let length;
  if (firstLen === 0x80) {
    throw new PasskeyError(ErrorCode.DECODE_ERROR, 'der: indefinite length is not permitted');
  } else if (firstLen < 0x80) {
    length = firstLen;
  } else {
    const nBytes = firstLen & 0x7f;
    if (nBytes === 0 || nBytes > 4) {
      // Zero-length long form is reserved for future use; more than
      // 4 bytes wouldn't fit a sensible payload.
      throw new PasskeyError(ErrorCode.DECODE_ERROR, `der: unsupported long-form length count ${nBytes}`);
    }
    if (pos + nBytes > bytes.byteLength) {
      throw new PasskeyError(ErrorCode.DECODE_ERROR, 'der: truncated inside long-form length');
    }
    // Accumulate with multiplication, not a signed `<<` shift: a
    // 4-byte length with the top bit set would overflow int32 and go
    // negative, defeating the bounds check below and silently
    // mis-parsing a hostile certificate.
    length = 0;
    for (let i = 0; i < nBytes; i += 1) {
      length = length * 256 + bytes[pos++];
    }
  }

  if (pos + length > bytes.byteLength) {
    throw new PasskeyError(
      ErrorCode.DECODE_ERROR,
      `der: TLV declares ${length} bytes but only ${bytes.byteLength - pos} available`,
    );
  }

  const contents = bytes.subarray(pos, pos + length);
  const totalLength = pos - offset + length;

  return { tag, tagClass, constructed, tagNumber, contents, totalLength };
}

/**
 * Read every child TLV inside a SEQUENCE / SET body.
 *
 * @param {Uint8Array} contents  the `contents` slice of a SEQUENCE / SET TLV
 * @returns {Tlv[]}
 */
export function readChildren(contents) {
  if (!(contents instanceof Uint8Array)) {
    throw new PasskeyError(ErrorCode.DECODE_ERROR, 'der: expected Uint8Array');
  }
  const out = [];
  let pos = 0;
  while (pos < contents.byteLength) {
    const t = readTlv(contents, pos);
    out.push(t);
    pos += t.totalLength;
  }
  return out;
}

/**
 * Convenience: read a top-level TLV, assert its tag, return the
 * children of its contents.
 *
 * @param {Uint8Array} bytes
 * @param {number} expectedTag  e.g. `TAG.SEQUENCE` or `contextTag(3)`
 * @returns {Tlv[]}
 */
export function intoSequence(bytes, expectedTag = TAG.SEQUENCE) {
  const t = readTlv(bytes);
  if (t.tag !== expectedTag) {
    throw new PasskeyError(
      ErrorCode.DECODE_ERROR,
      `der: expected tag 0x${expectedTag.toString(16)}, got 0x${t.tag.toString(16)}`,
    );
  }
  return readChildren(t.contents);
}

/**
 * Decode an OBJECT IDENTIFIER's contents into the dotted decimal
 * form used in RFCs (e.g. `"1.3.6.1.4.1.45724.1.1.4"`).
 *
 * X.690 §8.19: the first octet encodes the first two subidentifiers
 * as `40 * a + b` (where `a` is 0/1/2 and `b < 40` when `a < 2`);
 * subsequent subidentifiers are base-128, high bit set on all but
 * the final byte.
 *
 * @param {Uint8Array} contents  the `contents` slice of an OID TLV
 * @returns {string}
 */
export function decodeOid(contents) {
  if (!(contents instanceof Uint8Array) || contents.byteLength === 0) {
    throw new PasskeyError(ErrorCode.DECODE_ERROR, 'der: OID must be a non-empty Uint8Array');
  }

  const first = contents[0];
  const initial = first < 80 ? [Math.floor(first / 40), first % 40] : [2, first - 80];
  const parts = initial.map(String);

  let acc = 0n;
  let started = false;
  for (let i = 1; i < contents.byteLength; i += 1) {
    const b = contents[i];
    // Reject leading 0x80 in a multi-byte subidentifier — that would
    // encode a redundant leading zero, forbidden by X.690 §8.19.2.
    if (!started && b === 0x80) {
      throw new PasskeyError(ErrorCode.DECODE_ERROR, 'der: OID subidentifier has non-minimal encoding (leading 0x80)');
    }
    started = true;
    acc = (acc << 7n) | BigInt(b & 0x7f);
    if ((b & 0x80) === 0) {
      parts.push(acc.toString(10));
      acc = 0n;
      started = false;
    }
  }
  if (started) {
    throw new PasskeyError(ErrorCode.DECODE_ERROR, 'der: OID truncated (last byte has continuation bit set)');
  }

  return parts.join('.');
}

/**
 * Encode a dotted-decimal OID into its DER `contents` bytes. Handy
 * for compile-time OID tables and for tests; hot paths should just
 * compare the decoded string.
 *
 * @param {string} oid
 * @returns {Uint8Array}
 */
export function encodeOid(oid) {
  const parts = oid.split('.').map(p => {
    const n = BigInt(p);
    if (n < 0n) {
      throw new PasskeyError(ErrorCode.DECODE_ERROR, `der: OID part ${p} is negative`);
    }
    return n;
  });
  if (parts.length < 2) {
    throw new PasskeyError(ErrorCode.DECODE_ERROR, 'der: OID needs at least two components');
  }
  const [a, b] = parts;
  if (a > 2n || (a < 2n && b >= 40n)) {
    throw new PasskeyError(ErrorCode.DECODE_ERROR, `der: OID head ${a}.${b} violates X.690 constraints`);
  }
  const out = [Number(a * 40n + b)];
  for (let i = 2; i < parts.length; i += 1) {
    const chunks = [];
    let n = parts[i];
    if (n === 0n) {
      chunks.push(0);
    } else {
      while (n > 0n) {
        chunks.push(Number(n & 0x7fn));
        n >>= 7n;
      }
    }
    chunks.reverse();
    for (let j = 0; j < chunks.length - 1; j += 1) {
      out.push(chunks[j] | 0x80);
    }
    out.push(chunks[chunks.length - 1]);
  }
  return new Uint8Array(out);
}

/**
 * Locate an extension by OID inside an X.509 certificate's raw DER
 * bytes and return its `extnValue` OCTET STRING contents — i.e. the
 * bytes typically parsed again as an inner ASN.1 structure per RFC
 * 5280 §4.2.
 *
 * Returns `null` when the extension is absent. Throws when the
 * certificate itself is malformed.
 *
 * Certificate structure (RFC 5280 §4.1):
 *
 *   Certificate ::= SEQUENCE {
 *     tbsCertificate       TBSCertificate,
 *     signatureAlgorithm   AlgorithmIdentifier,
 *     signature            BIT STRING
 *   }
 *
 *   TBSCertificate ::= SEQUENCE {
 *     version         [0] EXPLICIT Version DEFAULT v1,
 *     serialNumber        CertificateSerialNumber,
 *     signature           AlgorithmIdentifier,
 *     issuer              Name,
 *     validity            Validity,
 *     subject             Name,
 *     subjectPublicKeyInfo SubjectPublicKeyInfo,
 *     issuerUniqueID  [1] IMPLICIT UniqueIdentifier OPTIONAL,
 *     subjectUniqueID [2] IMPLICIT UniqueIdentifier OPTIONAL,
 *     extensions      [3] EXPLICIT Extensions OPTIONAL
 *   }
 *
 *   Extension ::= SEQUENCE {
 *     extnID     OBJECT IDENTIFIER,
 *     critical   BOOLEAN DEFAULT FALSE,
 *     extnValue  OCTET STRING
 *   }
 *
 * @param {Uint8Array} certDer  raw DER-encoded certificate
 * @param {string} oid          dotted-decimal OID to find
 * @returns {Uint8Array | null}
 */
export function findExtension(certDer, oid) {
  if (!isString(oid)) {
    throw new PasskeyError(ErrorCode.DECODE_ERROR, 'der.findExtension: oid must be a string');
  }

  const [tbs] = intoSequence(certDer, TAG.SEQUENCE);
  if (!tbs || tbs.tag !== TAG.SEQUENCE) {
    throw new PasskeyError(ErrorCode.DECODE_ERROR, 'der: certificate first element is not TBSCertificate');
  }
  const tbsFields = readChildren(tbs.contents);

  // extensions [3] EXPLICIT — always the last context-specific
  // element inside the TBSCertificate we care about. Walk to find
  // it; skip anything else without introspecting.
  const extsHolder = tbsFields.find(t => t.tag === contextTag(3));
  if (!extsHolder) {
    return null;
  }

  // [3] EXPLICIT wraps a SEQUENCE OF Extension.
  const extsSeqChildren = intoSequence(extsHolder.contents, TAG.SEQUENCE);

  for (const ext of extsSeqChildren) {
    if (ext.tag !== TAG.SEQUENCE) {
      continue;
    }
    const parts = readChildren(ext.contents);
    if (parts.length === 0 || parts[0].tag !== TAG.OBJECT_IDENTIFIER) {
      continue;
    }
    if (decodeOid(parts[0].contents) !== oid) {
      continue;
    }
    // parts[1] is either the optional BOOLEAN `critical` or the
    // OCTET STRING `extnValue` — the extension value is always the
    // last element.
    const last = parts[parts.length - 1];
    if (last.tag !== TAG.OCTET_STRING) {
      throw new PasskeyError(ErrorCode.DECODE_ERROR, `der: extension ${oid} extnValue is not an OCTET STRING`);
    }
    return last.contents;
  }

  return null;
}
