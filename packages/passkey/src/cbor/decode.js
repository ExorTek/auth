/**
 * CBOR decoder — WebAuthn subset of RFC 8949.
 *
 * WebAuthn hands us CBOR in three places: the attestation object
 * (`{ fmt, authData, attStmt }` map), the COSE key inside authData
 * (int-keyed map), and the authenticator extensions map. All three
 * are definite-length maps with int / text keys and byte-string /
 * text-string / int / bool values, plus the occasional nested map.
 *
 * The decoder covers major types 0–5 and 7. Two behaviours are
 * deliberately restrictive:
 *
 *   1. Indefinite-length items (major type "byte length" 31) throw.
 *      WebAuthn does not produce them; accepting them would let an
 *      attestation craft a lopsided stream to confuse downstream
 *      parsers.
 *   2. Tags (major type 6) throw. WebAuthn's CBOR uses no tags at
 *      the outer envelope. Add support here the day a real
 *      authenticator needs it, not before.
 *
 * Returns:
 *
 *   - byte strings  → `Uint8Array`
 *   - text strings  → `string`
 *   - arrays        → `Array`
 *   - maps          → `Map` (COSE keys are negative ints — a plain
 *                     object would stringify them and lose the type)
 *   - unsigned/negative ints in the safe range → `number`
 *   - integers outside `Number.MAX_SAFE_INTEGER` → `bigint`
 *   - `true` / `false` / `null` / `undefined` as themselves
 *   - half / single / double floats → `number`
 */

class Cursor {
  /**
   * @param {Uint8Array} bytes
   */
  constructor(bytes) {
    this.bytes = bytes;
    this.pos = 0;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  need(n) {
    if (this.pos + n > this.bytes.byteLength) {
      throw new Error(`cbor: unexpected end of input (want ${n} bytes at offset ${this.pos})`);
    }
  }

  readU8() {
    this.need(1);
    return this.bytes[this.pos++];
  }

  readU16() {
    this.need(2);
    const v = this.view.getUint16(this.pos, false);
    this.pos += 2;
    return v;
  }

  readU32() {
    this.need(4);
    const v = this.view.getUint32(this.pos, false);
    this.pos += 4;
    return v;
  }

  readU64() {
    this.need(8);
    const v = this.view.getBigUint64(this.pos, false);
    this.pos += 8;
    return v;
  }

  readF16() {
    this.need(2);
    // IEEE 754 binary16 — implemented inline; no browser Float16Array yet.
    const raw = this.view.getUint16(this.pos, false);
    this.pos += 2;
    const sign = (raw & 0x8000) >> 15;
    const exp = (raw & 0x7c00) >> 10;
    const frac = raw & 0x03ff;
    let value;
    if (exp === 0) {
      value = 2 ** -14 * (frac / 1024);
    } else if (exp === 0x1f) {
      value = frac ? Number.NaN : Infinity;
    } else {
      value = 2 ** (exp - 15) * (1 + frac / 1024);
    }
    return sign ? -value : value;
  }

  readF32() {
    this.need(4);
    const v = this.view.getFloat32(this.pos, false);
    this.pos += 4;
    return v;
  }

  readF64() {
    this.need(8);
    const v = this.view.getFloat64(this.pos, false);
    this.pos += 8;
    return v;
  }

  readBytes(n) {
    this.need(n);
    // Slice into a fresh Uint8Array so downstream mutations don't
    // reach the original attestation buffer.
    const out = this.bytes.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
}

/**
 * Decode the argument portion of a CBOR head — the length or value
 * carried alongside the initial byte. Values 0–23 are inline, 24
 * means a following u8, 25 u16, 26 u32, 27 u64. 28–30 are reserved
 * and 31 is the indefinite-length marker we reject.
 *
 * @param {Cursor} c
 * @param {number} info  low 5 bits of the initial byte
 * @returns {number | bigint}
 */
function readArgument(c, info) {
  if (info < 24) {
    return info;
  }
  if (info === 24) {
    return c.readU8();
  }
  if (info === 25) {
    return c.readU16();
  }
  if (info === 26) {
    return c.readU32();
  }
  if (info === 27) {
    return c.readU64();
  }
  if (info === 31) {
    throw new Error('cbor: indefinite-length items are not supported');
  }
  throw new Error(`cbor: reserved additional-info value ${info}`);
}

/**
 * Coerce a `bigint` that fits in a JS safe integer back to `number`.
 * We produce `bigint` only when the value would otherwise silently
 * lose precision.
 */
function normaliseInt(v) {
  if (typeof v === 'bigint') {
    if (v <= BigInt(Number.MAX_SAFE_INTEGER) && v >= BigInt(Number.MIN_SAFE_INTEGER)) {
      return Number(v);
    }
    return v;
  }
  return v;
}

/**
 * @param {Cursor} c
 */
function readItem(c) {
  const initial = c.readU8();
  const major = initial >> 5;
  const info = initial & 0x1f;

  if (major === 0) {
    // Unsigned integer.
    return normaliseInt(readArgument(c, info));
  }

  if (major === 1) {
    // Negative integer — value = -1 - argument.
    const arg = readArgument(c, info);
    if (typeof arg === 'bigint') {
      return normaliseInt(-1n - arg);
    }
    return -1 - arg;
  }

  if (major === 2) {
    // Byte string.
    const len = readArgument(c, info);
    if (typeof len === 'bigint') {
      throw new Error(`cbor: byte string length ${len} exceeds Number.MAX_SAFE_INTEGER`);
    }
    return c.readBytes(len);
  }

  if (major === 3) {
    // Text string — decoded strictly (invalid UTF-8 throws).
    const len = readArgument(c, info);
    if (typeof len === 'bigint') {
      throw new Error(`cbor: text string length ${len} exceeds Number.MAX_SAFE_INTEGER`);
    }
    const raw = c.readBytes(len);
    return new TextDecoder('utf-8', { fatal: true }).decode(raw);
  }

  if (major === 4) {
    // Array.
    const len = readArgument(c, info);
    if (typeof len === 'bigint') {
      throw new Error(`cbor: array length ${len} exceeds Number.MAX_SAFE_INTEGER`);
    }
    const out = new Array(len);
    for (let i = 0; i < len; i += 1) {
      out[i] = readItem(c);
    }
    return out;
  }

  if (major === 5) {
    // Map — return as `Map` so int keys survive.
    const len = readArgument(c, info);
    if (typeof len === 'bigint') {
      throw new Error(`cbor: map length ${len} exceeds Number.MAX_SAFE_INTEGER`);
    }
    const out = new Map();
    for (let i = 0; i < len; i += 1) {
      const key = readItem(c);
      const value = readItem(c);
      if (out.has(key)) {
        // Duplicate keys are legal CBOR but not deterministic — for a
        // security-critical parser we reject rather than silently pick
        // one, matching the RFC 8949 §5.6 "strict decoder" guidance.
        throw new Error(`cbor: duplicate map key ${String(key)}`);
      }
      out.set(key, value);
    }
    return out;
  }

  if (major === 6) {
    throw new Error(`cbor: tags (major type 6) are not supported`);
  }

  // Major type 7 — floats + simple values.
  if (info < 20) {
    throw new Error(`cbor: reserved simple value ${info}`);
  }
  if (info === 20) {
    return false;
  }
  if (info === 21) {
    return true;
  }
  if (info === 22) {
    return null;
  }
  if (info === 23) {
    return undefined;
  }
  if (info === 24) {
    const simple = c.readU8();
    // Simple values 32–255 are unassigned; 0–19 and 32+ are legal
    // slots but WebAuthn never uses them.
    throw new Error(`cbor: unsupported simple value ${simple}`);
  }
  if (info === 25) {
    return c.readF16();
  }
  if (info === 26) {
    return c.readF32();
  }
  if (info === 27) {
    return c.readF64();
  }
  throw new Error(`cbor: reserved additional-info value ${info} in major type 7`);
}

/**
 * Decode a single top-level CBOR item from `bytes`. Trailing bytes
 * throw — WebAuthn structures are self-contained and any leftover
 * suggests a truncation or injection attempt.
 *
 * @param {Uint8Array} bytes
 * @returns {unknown}
 */
export function decode(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new Error('cbor.decode: expected Uint8Array');
  }
  const c = new Cursor(bytes);
  const value = readItem(c);
  if (c.pos !== bytes.byteLength) {
    throw new Error(`cbor: ${bytes.byteLength - c.pos} trailing byte(s) after top-level item`);
  }
  return value;
}

/**
 * Decode one item and report how many bytes it consumed. Used by
 * parsers that read a CBOR blob followed by other data — the
 * authenticator extensions map at the tail of authData is one such
 * spot.
 *
 * @param {Uint8Array} bytes
 * @returns {{ value: unknown, bytesRead: number }}
 */
export function decodeWithLength(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new Error('cbor.decodeWithLength: expected Uint8Array');
  }
  const c = new Cursor(bytes);
  const value = readItem(c);
  return { value, bytesRead: c.pos };
}
