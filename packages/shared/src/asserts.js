/**
 * Imperative single-argument guard helpers — the everyday
 * `assertPositiveInt(x, 'name')` shape used at API boundaries.
 * Companion to the compound schema builder in
 * `@exortek/shared/validate`: **schema** for whole options objects,
 * **asserts** for one-liner argument guards at the call site.
 *
 * Every guard is exported as a `make…` **factory** taking the binding
 * package's `wrap` and returning the guard itself. A package binds the
 * guards it calls once, in its `internal/guards.js`, so every argument
 * failure throws that package's error class — `err instanceof
 * CryptoError` holds, and users see at a glance which package raised it.
 *
 *   // packages/<pkg>/src/internal/guards.js
 *   import { makeAssertString, makeInvalidArgument } from '@exortek/shared/asserts';
 *   import { CryptoError, ErrorCode } from '../errors.js';
 *
 *   const wrap = (message, extra) => new CryptoError(ErrorCode.INVALID_ARGUMENT, message, extra);
 *
 *   export const assertString = makeAssertString(wrap);
 *   export const invalidArgument = makeInvalidArgument(wrap);
 *
 * Importing each factory by name is what makes the module
 * tree-shakeable. An earlier version handed back one object carrying
 * every guard, so all of them shipped in every package's bundle no
 * matter how few were used — `assertBoolean` reached fifteen published
 * packages without a single call site. Import what you call.
 *
 * **Path naming convention** (used as the `name` argument):
 *
 *   `<publicFunction>[.options|.config][.<field>]`
 *
 *   - `assertString(name, 'createUser.name')`            — top-level arg
 *   - `assertPositiveInt(n, 'scrypt.options.r')`         — nested option
 *   - `assertBytesOrString(pwd, 'pepper.wrap.password')` — method arg
 *
 * Keep the path short: the emitted error is `"<name> must be <desc>"`,
 * so a stack-line grep already tells the caller which function fired.
 * Reserve `hint` for actionable follow-ups ("pass the bytes returned by
 * encryptSymmetric()"), not for restating the field.
 */

/**
 * @typedef {{ cause?: unknown }} WrapExtra
 *   Extra options forwarded to the wrap function, so `invalidArgument`
 *   sites that catch an underlying error can preserve the `cause` chain
 *   without falling back to a raw `new PackageError(...)`.
 *
 * @typedef {(message: string, extra?: WrapExtra) => Error} WrapFn
 *   Constructs (never throws) the binding package's error, e.g.
 *   `(m, { cause } = {}) => new CryptoError(ErrorCode.INVALID_ARGUMENT, m, { cause })`.
 *
 * @typedef {{ hint?: string }} AssertOptions
 *   `hint` is appended to the message after an em-dash — use it for
 *   actionable guidance ("pass the exact bytes returned by …").
 *
 * @typedef {{ safeParse: (input: unknown, path?: string) => { ok: true, value: unknown } | { ok: false, errors: string[] } }} ParseableSchema
 *
 * @typedef {(wrap: WrapFn) => Function} GuardFactory
 */

/**
 * Build the failure message. `description` completes the sentence
 * `"<name> must be <description>"`; `hint` (optional) follows an em-dash.
 *
 * @param {string} name
 * @param {string} description
 * @param {string} [hint]
 * @returns {string}
 */
function message(name, description, hint) {
  return `${name} must be ${description}${hint ? ` — ${hint}` : ''}`;
}

/**
 * Shape a guard factory that fails whenever `predicate` returns false.
 *
 * @param {(value: unknown, opts?: any) => boolean} predicate
 * @param {string | ((opts?: any) => string)} description
 * @returns {GuardFactory}
 */
function guard(predicate, description) {
  return wrap => (value, name, opts) => {
    if (!predicate(value, opts)) {
      const desc = typeof description === 'function' ? description(opts) : description;
      throw wrap(message(name, desc, opts?.hint));
    }
  };
}

const ENCODINGS = new Set(['hex', 'base64', 'base64url']);

const isPlainObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);

/**
 * Construct (not throw) the bound error with a free-form message — for
 * `throw invalidArgument('…')` sites that don't fit the `X must be Y`
 * shape (canonicalisation errors, cross-field constraint failures). Pass
 * `{ cause }` when the failure was triggered by an underlying throw whose
 * chain matters (e.g. `JSON.stringify` on a bigint).
 *
 * @type {(wrap: WrapFn) => (msg: string, extra?: WrapExtra) => Error}
 */
export const makeInvalidArgument = wrap => (msg, extra) => wrap(msg, extra);

/**
 * Validate `input` against a `@exortek/shared/validate` schema; failures
 * throw the bound error carrying every collected message. The bridge that
 * keeps schema validation on the package's own error surface.
 *
 * @type {(wrap: WrapFn) => (schema: ParseableSchema, input: unknown, path?: string) => unknown}
 */
export const makeParse =
  wrap =>
  (schema, input, path = 'options') => {
    const r = schema.safeParse(input, path);
    if (!r.ok) {
      throw wrap(r.errors.join('; '));
    }
    return r.value;
  };

/** Assert that `value` is a non-negative safe integer (`0, 1, 2, …`). */
export const makeAssertNonNegativeInt = guard(
  v => Number.isSafeInteger(v) && /** @type {number} */ (v) >= 0,
  'a non-negative safe integer',
);

/** Assert that `value` is a strictly positive safe integer (`1, 2, 3, …`). */
export const makeAssertPositiveInt = guard(
  v => Number.isSafeInteger(v) && /** @type {number} */ (v) > 0,
  'a positive integer',
);

/**
 * Assert that `value` fits in a 48-bit unsigned integer (`0 … 2^48 − 1`).
 * Used for Unix millisecond timestamps in UUID v7 / ULID.
 */
export const makeAssertUint48 = guard(
  v => Number.isSafeInteger(v) && /** @type {number} */ (v) >= 0 && /** @type {number} */ (v) <= 0xffffffffffff,
  'a non-negative safe integer ≤ 2^48 − 1 (Unix ms since epoch)',
);

/** Assert that `value` is a string (may be empty). */
export const makeAssertString = guard(v => typeof v === 'string', 'a string');

/** Assert that `value` is a non-empty string. */
export const makeAssertNonEmptyString = guard(v => typeof v === 'string' && v.length > 0, 'a non-empty string');

/** Assert that `value` is a boolean. */
export const makeAssertBoolean = guard(v => typeof v === 'boolean', 'a boolean');

/** Assert that `value` is a function. */
export const makeAssertFunction = guard(v => typeof v === 'function', 'a function');

/**
 * Assert that `value` is a plain object (not `null`, not an array, not a
 * primitive).
 */
export const makeAssertObject = guard(isPlainObject, 'an object');

/**
 * Assert that `value` is either `undefined` or a plain object — the
 * "optional options object" pattern.
 */
export const makeAssertOptionalObject = guard(v => v === undefined || isPlainObject(v), 'an object');

/**
 * Assert that `value` is a byte buffer (`Buffer` or `Uint8Array`) —
 * strings are NOT accepted. For already-encoded material where a string
 * would be ambiguous (ciphertext, signatures, raw key bytes).
 */
export const makeAssertBytes = guard(v => Buffer.isBuffer(v) || v instanceof Uint8Array, 'a Buffer or Uint8Array');

/** Assert that `value` is either a string or a byte buffer. */
export const makeAssertBytesOrString = guard(
  v => typeof v === 'string' || Buffer.isBuffer(v) || v instanceof Uint8Array,
  'a string or Buffer',
);

/**
 * Assert that `encoding` is one of the accepted output/input encodings.
 * Pass `allowBuffer: false` where a `Buffer` output makes no sense
 * (verifying a string signature, decoding a token payload).
 */
export const makeAssertEncoding = guard(
  (value, opts) =>
    (typeof value === 'string' && ENCODINGS.has(value)) || (opts?.allowBuffer !== false && value === 'buffer'),
  opts =>
    opts?.allowBuffer !== false ? "'hex', 'base64', 'base64url', or 'buffer'" : "'hex', 'base64', or 'base64url'",
);
