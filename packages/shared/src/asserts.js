/**
 * Imperative single-argument guard helpers — the everyday
 * `assertPositiveInt(x, 'options.iterations')` shape used at API
 * boundaries. Companion to the compound schema builder in
 * `@exortek/shared/validate`: **schema** for whole options objects,
 * **asserts** for one-liner argument guards at the call site.
 *
 * The consumer-facing surface is {@link bindAsserts}: each package
 * binds the full assert set to its own typed error class once (in
 * `internal/guards.js`), so every argument failure throws that
 * package's class — `err instanceof CryptoError` holds and users see
 * at a glance which package raised the error. The bound `parse`
 * bridges `@exortek/shared/validate` schemas to the same error class.
 */

/**
 * @typedef {(message: string) => Error} WrapFn
 *   Constructs (never throws) the binding package's error, e.g.
 *   `(m) => new CryptoError(ErrorCode.INVALID_ARGUMENT, m)`.
 *
 * @typedef {{ hint?: string }} AssertOptions
 *   `hint` is appended to the message after an em-dash — use it for
 *   actionable guidance ("pass the exact bytes returned by …").
 *
 * @typedef {{ safeParse: (input: unknown, path?: string) => { ok: true, value: unknown } | { ok: false, errors: string[] } }} ParseableSchema
 */

/**
 * Build the failure message. `description` completes the sentence
 * `"<name> must be <description>"`; `hint` (optional) follows an
 * em-dash.
 *
 * @param {string} name
 * @param {string} description
 * @param {string} [hint]
 * @returns {string}
 */
function message(name, description, hint) {
  return `${name} must be ${description}${hint ? ` — ${hint}` : ''}`;
}

const ENCODINGS = new Set(['hex', 'base64', 'base64url']);

/**
 * Bind the assert set to a package's error class. Call once per
 * package (conventionally in `internal/guards.js`) and import the
 * bound object everywhere:
 *
 *   import { bindAsserts } from '@exortek/shared/asserts';
 *   import { CryptoError, ErrorCode } from '../errors.js';
 *   export const g = bindAsserts((m) => new CryptoError(ErrorCode.INVALID_ARGUMENT, m));
 *
 *   // call sites:
 *   g.assertPositiveInt(options.iterations, 'options.iterations');
 *   const cfg = g.parse(OptionsSchema, options, 'options');
 *
 * @param {WrapFn} wrap
 */
export function bindAsserts(wrap) {
  /**
   * @param {string} name
   * @param {string} description
   * @param {AssertOptions} [opts]
   * @returns {never}
   */
  function fail(name, description, opts) {
    throw wrap(message(name, description, opts?.hint));
  }

  /**
   * Assert that `value` is a plain object (not `null`, not an array,
   * not a primitive).
   * @param {unknown} value
   * @param {string}  name
   * @param {AssertOptions} [opts]
   */
  function assertObject(value, name, opts) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      fail(name, 'an object', opts);
    }
  }

  return {
    /**
     * Construct (not throw) the bound error with a free-form message —
     * for `throw g.invalidArgument('…')` sites that don't fit the
     * `X must be Y` shape (canonicalisation errors, cross-field
     * constraint failures).
     *
     * @param {string} msg
     * @returns {Error}
     */
    invalidArgument(msg) {
      return wrap(msg);
    },

    /**
     * Validate `input` against a `@exortek/shared/validate` schema;
     * failures throw the bound error carrying every collected message.
     * The bridge that keeps schema validation on the package's own
     * error surface.
     *
     * @param {ParseableSchema} schema
     * @param {unknown} input
     * @param {string} [path='options']
     * @returns {unknown} the parsed (possibly defaulted) value
     */
    parse(schema, input, path = 'options') {
      const r = schema.safeParse(input, path);
      if (!r.ok) {
        throw wrap(r.errors.join('; '));
      }
      return r.value;
    },

    /**
     * Assert that `value` is a non-negative safe integer (`0, 1, 2, …`).
     * @param {unknown} value
     * @param {string}  name  Argument name to include in the error message.
     * @param {AssertOptions} [opts]
     */
    assertNonNegativeInt(value, name, opts) {
      if (!Number.isSafeInteger(value) || /** @type {number} */ (value) < 0) {
        fail(name, 'a non-negative safe integer', opts);
      }
    },

    /**
     * Assert that `value` is a strictly positive safe integer (`1, 2, 3, …`).
     * @param {unknown} value
     * @param {string}  name
     * @param {AssertOptions} [opts]
     */
    assertPositiveInt(value, name, opts) {
      if (!Number.isSafeInteger(value) || /** @type {number} */ (value) <= 0) {
        fail(name, 'a positive integer', opts);
      }
    },

    /**
     * Assert that `value` fits in a 48-bit unsigned integer (`0 … 2^48 − 1`).
     * Used for Unix millisecond timestamps in UUID v7 / ULID.
     * @param {unknown} value
     * @param {string}  name
     * @param {AssertOptions} [opts]
     */
    assertUint48(value, name, opts) {
      if (
        !Number.isSafeInteger(value) ||
        /** @type {number} */ (value) < 0 ||
        /** @type {number} */ (value) > 0xffffffffffff
      ) {
        fail(name, 'a non-negative safe integer ≤ 2^48 − 1 (Unix ms since epoch)', opts);
      }
    },

    /**
     * Assert that `value` is a string (may be empty).
     * @param {unknown} value
     * @param {string}  name
     * @param {AssertOptions} [opts]
     */
    assertString(value, name, opts) {
      if (typeof value !== 'string') {
        fail(name, 'a string', opts);
      }
    },

    /**
     * Assert that `value` is a non-empty string.
     * @param {unknown} value
     * @param {string}  name
     * @param {AssertOptions} [opts]
     */
    assertNonEmptyString(value, name, opts) {
      if (typeof value !== 'string' || value.length === 0) {
        fail(name, 'a non-empty string', opts);
      }
    },

    /**
     * Assert that `value` is a boolean.
     * @param {unknown} value
     * @param {string}  name
     * @param {AssertOptions} [opts]
     */
    assertBoolean(value, name, opts) {
      if (typeof value !== 'boolean') {
        fail(name, 'a boolean', opts);
      }
    },

    /**
     * Assert that `value` is a function.
     * @param {unknown} value
     * @param {string}  name
     * @param {AssertOptions} [opts]
     */
    assertFunction(value, name, opts) {
      if (typeof value !== 'function') {
        fail(name, 'a function', opts);
      }
    },

    assertObject,

    /**
     * Assert that `value` is either `undefined` or a plain object —
     * the "optional options object" pattern.
     * @param {unknown} value
     * @param {string}  name
     * @param {AssertOptions} [opts]
     */
    assertOptionalObject(value, name, opts) {
      if (value === undefined) {
        return;
      }
      assertObject(value, name, opts);
    },

    /**
     * Assert that `value` is a byte buffer (`Buffer` or `Uint8Array`) —
     * strings are NOT accepted. For already-encoded material where a
     * string would be ambiguous (ciphertext, signatures, raw key bytes).
     * @param {unknown} value
     * @param {string}  name
     * @param {AssertOptions} [opts]
     */
    assertBytes(value, name, opts) {
      if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
        fail(name, 'a Buffer or Uint8Array', opts);
      }
    },

    /**
     * Assert that `value` is either a string or a byte buffer (`Buffer`
     * or `Uint8Array`).
     * @param {unknown} value
     * @param {string}  name
     * @param {AssertOptions} [opts]
     */
    assertBytesOrString(value, name, opts) {
      if (typeof value !== 'string' && !Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
        fail(name, 'a string or Buffer', opts);
      }
    },

    /**
     * Assert that `encoding` is one of the accepted output/input
     * encodings. Pass `allowBuffer: false` where a `Buffer` output makes
     * no sense (verifying a string signature, decoding a token payload).
     *
     * @param {unknown} encoding
     * @param {string}  name
     * @param {AssertOptions & { allowBuffer?: boolean }} [opts]
     */
    assertEncoding(encoding, name, opts) {
      const allowBuffer = opts?.allowBuffer !== false;
      const valid = (typeof encoding === 'string' && ENCODINGS.has(encoding)) || (allowBuffer && encoding === 'buffer');
      if (!valid) {
        const list = allowBuffer ? "'hex', 'base64', 'base64url', or 'buffer'" : "'hex', 'base64', or 'base64url'";
        fail(name, list, opts);
      }
    },
  };
}
