/**
 * Distinguished-name comparison for `tls_client_auth` (RFC 8705 §2.1.2).
 * The registered `tlsClientAuthSubjectDn` is an RFC 4514 string; Node hands
 * the certificate subject over as an object of attribute values. Both are
 * reduced to a set of `TYPE=value` attributes and compared structurally, so
 * an escaped comma inside a value (`CN=foo\,O=Bank`) can never collide with
 * an extra attribute (`CN=foo,O=Bank`), and attribute order does not matter.
 */
import { isArray, isNonEmptyString, isObject, isString } from '@exortek/shared/predicates';

/**
 * Parse an RFC 4514 DN string into attributes.
 *
 * @param {string} dn
 * @returns {{ type: string, value: string }[] | undefined}  undefined when malformed
 */
export function parseDn(dn) {
  /** @type {{ type: string, value: string }[]} */
  const out = [];
  let type = '';
  /** @type {number[] | null} value bytes while reading a value, null while reading a type */
  let value = null;
  let trailingSpaces = 0;

  const flush = () => {
    if (value === null) {
      return false;
    }
    const t = type.trim();
    if (t.length === 0) {
      return false;
    }
    const bytes = trailingSpaces > 0 ? value.slice(0, value.length - trailingSpaces) : value;
    out.push({ type: t.toUpperCase(), value: Buffer.from(bytes).toString('utf8') });
    type = '';
    value = null;
    trailingSpaces = 0;
    return true;
  };

  for (let i = 0; i < dn.length; i++) {
    const ch = dn[i];
    if (value === null) {
      if (ch === '=') {
        value = [];
      } else if (ch === ',' || ch === '+' || ch === '\\') {
        return undefined;
      } else {
        type += ch;
      }
      continue;
    }
    if (ch === '\\') {
      const next = dn[i + 1];
      if (next === undefined) {
        return undefined;
      }
      if (/[0-9a-fA-F]/.test(next) && /[0-9a-fA-F]/.test(dn[i + 2] ?? '')) {
        value.push(Number.parseInt(dn.slice(i + 1, i + 3), 16));
        i += 2;
      } else {
        value.push(...Buffer.from(next, 'utf8'));
        i += 1;
      }
      trailingSpaces = 0;
      continue;
    }
    if (ch === ',' || ch === '+') {
      if (!flush()) {
        return undefined;
      }
      continue;
    }
    if (ch === ' ' && value.length === 0) {
      // Unescaped leading space after `=` is insignificant.
      continue;
    }
    if (ch === '#' && value.length === 0) {
      // Hex-encoded BER values are not supported for matching.
      return undefined;
    }
    value.push(...Buffer.from(ch, 'utf8'));
    trailingSpaces = ch === ' ' ? trailingSpaces + 1 : 0;
  }
  if (!flush()) {
    return undefined;
  }
  return out;
}

/**
 * Attributes of a certificate subject — Node's parsed object (multi-valued
 * attributes arrive as arrays) or an RFC 4514 string.
 *
 * @param {unknown} subject
 * @returns {{ type: string, value: string }[] | undefined}
 */
export function subjectAttributes(subject) {
  if (isNonEmptyString(subject)) {
    return parseDn(subject);
  }
  if (!isObject(subject)) {
    return undefined;
  }
  /** @type {{ type: string, value: string }[]} */
  const out = [];
  for (const [type, raw] of Object.entries(subject)) {
    for (const value of isArray(raw) ? raw : [raw]) {
      if (!isString(value)) {
        return undefined;
      }
      out.push({ type: type.toUpperCase(), value });
    }
  }
  return out;
}

/**
 * Whether two attribute lists name the same DN (order-insensitive).
 *
 * @param {{ type: string, value: string }[]} a
 * @param {{ type: string, value: string }[]} b
 * @returns {boolean}
 */
export function sameDn(a, b) {
  if (a.length === 0 || a.length !== b.length) {
    return false;
  }
  const key = attrs =>
    attrs
      .map(({ type, value }) => JSON.stringify([type, value]))
      .sort()
      .join('\n');
  return key(a) === key(b);
}
