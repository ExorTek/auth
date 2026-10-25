/**
 * Exact subject-attribute matching for attestation leaf certificates.
 *
 * Node renders `X509Certificate#subject` one RDN per line, escaping
 * separators inside values (`CN=evil\,CN=attest.android.com`). Matching
 * that string with a regex lets a crafted value smuggle in a fake
 * attribute; parsing it into `TYPE=value` pairs and comparing exactly
 * does not.
 */

/**
 * @param {string} subject   `X509Certificate#subject`
 * @returns {Array<[string, string]>}  [TYPE (upper-case), unescaped value]
 */
export function parseSubject(subject) {
  /** @type {Array<[string, string]>} */
  const out = [];
  for (const line of subject.replace(/\r/g, '').split('\n')) {
    const eq = line.indexOf('=');
    if (eq <= 0) {
      continue;
    }
    const type = line.slice(0, eq).trim().toUpperCase();
    const value = line.slice(eq + 1).replace(/\\(.)/g, '$1');
    out.push([type, value]);
  }
  return out;
}

/**
 * Whether the certificate subject carries `type` with exactly `value`
 * (attribute types compare case-insensitively, values exactly unless
 * `ignoreCase`).
 *
 * @param {string} subject
 * @param {string} type
 * @param {string} value
 * @param {{ ignoreCase?: boolean }} [options]
 * @returns {boolean}
 */
export function hasSubjectAttribute(subject, type, value, options = {}) {
  const want = options.ignoreCase ? value.toLowerCase() : value;
  return parseSubject(subject).some(
    ([t, v]) => t === type.toUpperCase() && (options.ignoreCase ? v.toLowerCase() : v) === want,
  );
}
