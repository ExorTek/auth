import crypto from 'node:crypto';
import { CryptoError, ErrorCode } from '../errors.js';
import { assertString, assertUint48 } from '../internal/guards.js';
import { toBuffer } from '../internal/bytes.js';
import { hash } from '../hash/hash.js';
import { decode as hexDecode } from '../encode/hex.js';
import { isString } from '@exortek/shared/predicates';

/** Canonical UUID format matcher (8-4-4-4-12, hex, case-insensitive). Version/variant bits are NOT checked — custom namespace UUIDs may carry any version, and RFC 9562 defines up to v8. */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Returns true if `value` is a string matching the canonical UUID format
 * (`8-4-4-4-12` lowercase or uppercase hex). Does not validate the version
 * or variant bits — accepts any well-formed UUID (nil, v1–v8, custom).
 *
 * @param {unknown} value
 * @returns {boolean}
 *
 * @example
 * isUUID(uuid4())                                  // true
 * isUUID('not-a-uuid')                             // false
 * isUUID('00000000-0000-0000-0000-000000000000')   // true (nil UUID)
 */
export function isUUID(value) {
  return isString(value) && UUID_RE.test(value);
}

/**
 * Format a 16-byte buffer as a canonical UUID string (`8-4-4-4-12`, lowercase hex).
 * Internal helper shared by `uuid5` and `uuid7` — `_` prefix marks it as
 * module-private (not exported, not part of the public API).
 *
 * @private
 * @param {Buffer | Uint8Array} bytes  Exactly 16 bytes.
 * @returns {string}
 */
function _stringifyUUID(bytes) {
  const h = Buffer.from(bytes.buffer, bytes.byteOffset, 16).toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/**
 * Standard UUID namespace for fully-qualified domain names (RFC 9562 §6.6).
 * Pass as the `namespace` argument to {@link uuid5} when hashing DNS-style strings.
 */
export const NAMESPACE_DNS = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';

/**
 * Standard UUID namespace for URLs (RFC 9562 §6.6).
 * Pass as the `namespace` argument to {@link uuid5} when hashing URLs.
 */
export const NAMESPACE_URL = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';

/**
 * Standard UUID namespace for ISO OIDs (RFC 9562 §6.6).
 */
export const NAMESPACE_OID = '6ba7b812-9dad-11d1-80b4-00c04fd430c8';

/**
 * Standard UUID namespace for X.500 distinguished names (RFC 9562 §6.6).
 */
export const NAMESPACE_X500 = '6ba7b814-9dad-11d1-80b4-00c04fd430c8';

/**
 * RFC 9562 UUID v4 — fully random.
 *
 * Thin wrapper over `crypto.randomUUID()`. 128 bits total: 122 unpredictable,
 * 6 reserved for version (`0100`) and variant (`10`) tags. Use this when you
 * need an opaque identifier with no ordering guarantees (session IDs,
 * request IDs, anything where sortability does not matter).
 *
 * @returns {string}  Lowercase canonical UUID (8-4-4-4-12), e.g. `'550e8400-e29b-41d4-a716-446655440000'`.
 *
 * @example
 * const sessionId = uuid4()
 *
 * @see https://www.rfc-editor.org/rfc/rfc9562#name-uuid-version-4
 */
export function uuid4() {
  return crypto.randomUUID();
}

let _lastMs = -1;
let _seq = 0;

/**
 * RFC 9562 UUID v7 — time-ordered, k-sortable.
 *
 * Layout: 48-bit Unix millisecond timestamp || 4-bit version (`0111`) ||
 * 32-bit monotonic sequence (spread across bytes 6–10) || 2-bit variant (`10`) ||
 * 42-bit random. Lexicographically sortable by creation time — excellent
 * database primary key (B-tree friendly, no page-split storms like fully
 * random v4).
 *
 * **Strict monotonicity guarantee** (default path): within a single process,
 * successive `uuid7()` calls are strictly ordered (`uuid7() < uuid7()`
 * always), even when invoked at the same millisecond. On 32-bit counter
 * overflow the timestamp is bumped by one ms to preserve ordering. System
 * clock regressions are ignored — we continue issuing UUIDs from the last
 * observed timestamp.
 *
 * Passing an explicit `time` bypasses the monotonic counter — useful for
 * backfilling historical records or event-sourced systems where event-time
 * differs from receive-time. Same-`time` calls are unordered.
 *
 * @param {number} [time]  Optional override timestamp in Unix milliseconds (UTC).
 *                         Must be a non-negative integer ≤ 2^48 − 1.
 *                         Defaults to `Date.now()`. Use `date.getTime()` for a `Date`.
 * @returns {string}       Lowercase canonical UUID (8-4-4-4-12) with v7 layout.
 * @throws {CryptoError}   With code `INVALID_ARGUMENT` if `time` is provided but
 *                         is not a non-negative integer within the 48-bit range.
 *
 * @example
 * uuid7()                                  // 'now', strict monotonic
 * uuid7() < uuid7() < uuid7()              // true (even within the same ms)
 *
 * @example
 * uuid7(event.createdAt.getTime())         // backfill with event time
 *
 * @see https://www.rfc-editor.org/rfc/rfc9562#name-uuid-version-7
 */
export function uuid7(time) {
  if (time !== undefined) {
    assertUint48(time, 'time');
  }

  // 4 bytes seed the seq on a new-ms boundary, 6 bytes fill the v7 random tail.
  const rnd = crypto.randomBytes(10);
  let ts;
  let seq;

  if (time !== undefined) {
    // Explicit timestamp — pure output, monotonic state untouched.
    ts = time;
    seq = rnd.readUInt32BE(0);
  } else {
    const now = Date.now();
    if (now > _lastMs) {
      _lastMs = now;
      _seq = rnd.readUInt32BE(0);
    } else {
      // Same ms OR system clock regression — increment counter and stay at
      // `_lastMs` so we never reuse or move backwards in time.
      _seq = (_seq + 1) >>> 0;
      if (_seq === 0) {
        // 32-bit overflow — borrow one millisecond from the future.
        _lastMs += 1;
      }
    }
    ts = _lastMs;
    seq = _seq;
  }

  // Layout (RFC 9562 §5.7, with 32-bit counter spread per uuidjs/uuid):
  //   bytes 0..5 : 48-bit timestamp                          (big-endian ms)
  //   byte  6    : version 0111 | seq[31..28]
  //   byte  7    : seq[27..20]
  //   byte  8    : variant 10  | seq[19..14]
  //   byte  9    : seq[13..6]
  //   byte 10    : seq[5..0]   | 2 random bits
  //   bytes 11..15: 40 random bits
  const buf = Buffer.allocUnsafe(16);
  buf.writeUIntBE(ts, 0, 6);
  buf[6] = 0x70 | ((seq >>> 28) & 0x0f);
  buf[7] = (seq >>> 20) & 0xff;
  buf[8] = 0x80 | ((seq >>> 14) & 0x3f);
  buf[9] = (seq >>> 6) & 0xff;
  buf[10] = ((seq << 2) & 0xfc) | (rnd[4] & 0x03);
  buf[11] = rnd[5];
  buf[12] = rnd[6];
  buf[13] = rnd[7];
  buf[14] = rnd[8];
  buf[15] = rnd[9];

  return _stringifyUUID(buf);
}

/**
 * RFC 9562 UUID v5 — namespaced, SHA-1 based, deterministic.
 *
 * Hashes `namespace + name` with SHA-1 and shapes the digest into a UUID
 * (sets version `0101` and variant `10` bits per spec). Calling with the
 * same `(namespace, name)` pair always returns the same UUID — useful for
 * content-addressable IDs, dedup keys, idempotency tokens.
 *
 * Use one of the predefined namespace constants ({@link NAMESPACE_DNS},
 * {@link NAMESPACE_URL}, {@link NAMESPACE_OID}, {@link NAMESPACE_X500}) or
 * a custom namespace UUID generated once for your domain.
 *
 * Note: SHA-1 is used per the v5 spec; v5 IDs are deterministic identifiers,
 * not cryptographic commitments — do not rely on SHA-1's collision resistance
 * for security-sensitive use cases. For unique random IDs use {@link uuid4}.
 *
 * @param {string} namespace  Namespace UUID in canonical 8-4-4-4-12 form.
 * @param {string} name       Name to hash within the namespace.
 * @returns {string}          Deterministic lowercase UUID (8-4-4-4-12) with v5 layout.
 * @throws {CryptoError}      With code `INVALID_ARGUMENT` if `namespace` is not a valid UUID string
 *                            or `name` is not a string.
 *
 * @example
 * import { uuid5, NAMESPACE_DNS } from '@exortek/crypto/random'
 * const id = uuid5(NAMESPACE_DNS, 'user@example.com')
 * // → always the same UUID for the same email
 *
 * @see https://www.rfc-editor.org/rfc/rfc9562#name-uuid-version-5
 */
export function uuid5(namespace, name) {
  assertString(namespace, 'namespace');
  if (!UUID_RE.test(namespace)) {
    throw new CryptoError(
      ErrorCode.INVALID_ARGUMENT,
      `namespace must be a valid UUID string in canonical 8-4-4-4-12 form; got ${JSON.stringify(namespace)}. Use one of the exported constants (NAMESPACE_DNS / NAMESPACE_URL / NAMESPACE_OID / NAMESPACE_X500) or your own uuid4().`,
    );
  }
  assertString(name, 'name');

  const namespaceBytes = hexDecode(namespace.replace(/-/g, ''));
  const nameBytes = toBuffer(name, 'name');
  const digest = /** @type {Buffer} */ (
    hash(Buffer.concat([namespaceBytes, nameBytes]), {
      algo: 'sha1',
      encoding: 'buffer',
    })
  );

  // First 16 of the 20-byte SHA-1 digest carry the UUID; set version/variant per RFC 9562 §5.5.
  digest[6] = (digest[6] & 0x0f) | 0x50; // version 0101 (v5)
  digest[8] = (digest[8] & 0x3f) | 0x80; // variant 10

  return _stringifyUUID(digest);
}
