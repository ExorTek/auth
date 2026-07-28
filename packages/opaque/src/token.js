/**
 * Opaque token generation — the entropy side of the package. No
 * signature, no embedded payload: a caller can't decode anything back
 * out of the string, only look it up via {@link create}/{@link verify}.
 */

import { random } from '@exortek/crypto';
import { assertObject, assertNonEmptyString, assertPositiveInt, invalidArgument } from './internal/guards.js';

/** @type {Record<string, (n: number) => string>} */
const GENERATORS = {
  hex: bytes => random.hex(bytes),
  base64url: bytes => random.base64url(bytes),
  base58: bytes => random.base58(bytes),
  crockford: bytes => random.crockford(bytes),
  ulid: () => random.ulid(),
  uuid4: () => random.uuid4(),
  uuid7: () => random.uuid7(),
  alphanumeric: length => random.alphanumeric(length),
};

const DEFAULT_GENERATOR = 'hex';

/**
 * @typedef {'hex' | 'base64url' | 'base58' | 'crockford' | 'ulid' | 'uuid4' | 'uuid7' | 'alphanumeric' | 'prefixed' | 'structured'} OpaqueTokenFormat
 */

/**
 * @typedef {object} GenerateOptions
 * @property {OpaqueTokenFormat} format
 * @property {number}  [bytes=32]      Entropy size for byte-based generators (`hex`, `base64url`, `base58`).
 * @property {number}  [length]        Output length for `alphanumeric` — defaults to `bytes` if omitted.
 * @property {keyof typeof GENERATORS} [generator='hex']  Which generator produces the entropy segment of a `prefixed` / `structured` token.
 * @property {string}  [prefix]        Required for `format: 'prefixed'` — e.g. `'usr'`.
 * @property {string}  [version]      Required for `format: 'structured'` — e.g. `'v1'`.
 * @property {string}  [type]         Required for `format: 'structured'` — a literal label embedded in the token, e.g. `'ref'`.
 * @property {string}  [separator='_'] Joins the segments of `prefixed` / `structured` tokens.
 */

/**
 * Generate an opaque token. `format` is either a bare generator name
 * (`'hex'`, `'uuid4'`, …) or a composite shape (`'prefixed'`,
 * `'structured'`) that wraps a generator's output with a literal label.
 *
 * @param {GenerateOptions} options
 * @returns {string}
 *
 * @example
 * generate({ format: 'hex', bytes: 32 })
 * // → '3f9a...'  (64 hex chars)
 *
 * generate({ format: 'prefixed', prefix: 'usr' })
 * // → 'usr_3f9a...'  (generator defaults to 'hex')
 *
 * generate({ format: 'structured', version: 'v1', type: 'ref', generator: 'ulid', separator: '.' })
 * // → 'v1.ref.01ARZ3NDEKTSV4RRFFQ69G5FAV'
 */
export function generate(options) {
  assertObject(options, 'generate.options');
  const { format, bytes = 32, length, generator = DEFAULT_GENERATOR, prefix, version, type, separator = '_' } = options;
  assertNonEmptyString(format, 'generate.options.format');

  if (format in GENERATORS) {
    const n = format === 'alphanumeric' ? (length ?? bytes) : bytes;
    assertPositiveInt(n, format === 'alphanumeric' ? 'generate.options.length' : 'generate.options.bytes');
    return GENERATORS[format](n);
  }

  const entropyGenerator = GENERATORS[generator];
  if (!entropyGenerator) {
    throw invalidArgument(
      `generate: unsupported generator ${JSON.stringify(generator)}. Expected one of: ${Object.keys(GENERATORS).join(', ')}`,
    );
  }
  const n = generator === 'alphanumeric' ? (length ?? bytes) : bytes;
  assertPositiveInt(n, generator === 'alphanumeric' ? 'generate.options.length' : 'generate.options.bytes');

  if (format === 'prefixed') {
    assertNonEmptyString(prefix, 'generate.options.prefix');
    return `${prefix}${separator}${entropyGenerator(n)}`;
  }

  if (format === 'structured') {
    assertNonEmptyString(version, 'generate.options.version');
    assertNonEmptyString(type, 'generate.options.type');
    return `${version}${separator}${type}${separator}${entropyGenerator(n)}`;
  }

  throw invalidArgument(
    `generate: unsupported format ${JSON.stringify(format)}. Expected one of: ${Object.keys(GENERATORS).join(', ')}, 'prefixed', 'structured'`,
  );
}
