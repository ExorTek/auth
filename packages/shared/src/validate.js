/**
 * Tiny schema builder — the shared validator used by every
 * `@exortek/*` package for config / option validation.
 *
 * Two use modes:
 *
 *   const opts = MySchema.parse(input, 'options');
 *     // throws Error whose message is a path-prefixed reason
 *
 *   const r = MySchema.safeParse(input, 'options');
 *     if (!r.ok) console.error(r.errors);
 *
 * Every primitive returns a `Validator` — a small object with `parse`,
 * `safeParse`, and `refine` methods. Validators compose freely
 * through `object`, `array`, `union`, `optional`, `nullable`.
 *
 * Consumers wrap thrown errors at their surface boundary if they need
 * a typed error class like `JwtError`.
 */

/**
 * @typedef {{ ok: true, value: unknown } | { ok: false, errors: string[] }} SafeResult
 * @typedef {(input: unknown, path: string, errors: string[]) => unknown} CheckFn
 * @typedef {Object} Validator
 * @property {(input: unknown, path?: string) => unknown} parse
 * @property {(input: unknown, path?: string) => SafeResult} safeParse
 * @property {(predicate: (v: unknown) => boolean, message: string) => Validator} refine
 */

/**
 * @param {CheckFn} check
 * @returns {Validator}
 */
function make(check) {
  return {
    parse(input, path = 'value') {
      const errors = [];
      const value = check(input, path, errors);
      if (errors.length > 0) {
        throw new Error(errors[0]);
      }
      return value;
    },
    safeParse(input, path = 'value') {
      const errors = [];
      const value = check(input, path, errors);
      return errors.length > 0 ? { ok: false, errors } : { ok: true, value };
    },
    refine(predicate, message) {
      return make((input, path, errors) => {
        const value = check(input, path, errors);
        if (errors.length > 0) {
          return input;
        }
        let ok;
        try {
          ok = predicate(value);
        } catch (err) {
          errors.push(`${path}: ${message} (${err instanceof Error ? err.message : String(err)})`);
          return input;
        }
        if (!ok) {
          errors.push(`${path}: ${message}; got ${describe(input)}`);
        }
        return value;
      });
    },
  };
}

// primitives

/**
 * @param {{ minLength?: number, maxLength?: number }} [opts]
 */
export function string(opts) {
  return make((input, path, errors) => {
    if (typeof input !== 'string') {
      errors.push(`${path}: expected string; got ${describe(input)}`);
      return input;
    }
    if (opts?.minLength !== undefined && input.length < opts.minLength) {
      errors.push(`${path}: expected string of at least ${opts.minLength} characters; got ${input.length}`);
    }
    if (opts?.maxLength !== undefined && input.length > opts.maxLength) {
      errors.push(`${path}: expected string of at most ${opts.maxLength} characters; got ${input.length}`);
    }
    return input;
  });
}

/**
 * @param {{ min?: number, max?: number }} [opts]
 */
export function number(opts) {
  return make((input, path, errors) => {
    if (typeof input !== 'number' || !Number.isFinite(input)) {
      errors.push(`${path}: expected finite number; got ${describe(input)}`);
      return input;
    }
    rangeCheck(input, path, errors, opts);
    return input;
  });
}

/**
 * Safe integer. `positiveInt()` / `nonNegativeInt()` below are the
 * shortcuts for the two overwhelmingly common ranges.
 *
 * @param {{ min?: number, max?: number }} [opts]
 */
export function int(opts) {
  return make((input, path, errors) => {
    if (!Number.isSafeInteger(input)) {
      errors.push(`${path}: expected integer; got ${describe(input)}`);
      return input;
    }
    rangeCheck(/** @type {number} */ (input), path, errors, opts);
    return input;
  });
}

/** Strictly positive safe integer (`1, 2, 3, …`). */
export function positiveInt() {
  return int({ min: 1 });
}

/** Non-negative safe integer (`0, 1, 2, …`). */
export function nonNegativeInt() {
  return int({ min: 0 });
}

export function boolean() {
  return make((input, path, errors) => {
    if (typeof input !== 'boolean') {
      errors.push(`${path}: expected boolean; got ${describe(input)}`);
    }
    return input;
  });
}

export function any() {
  return make(input => input);
}

/** `Buffer | Uint8Array` — secrets, keys, salts, ciphertext. */
export function bytes() {
  return make((input, path, errors) => {
    if (!Buffer.isBuffer(input) && !(input instanceof Uint8Array)) {
      errors.push(`${path}: expected Buffer or Uint8Array; got ${describe(input)}`);
    }
    return input;
  });
}

/** The secret-input convention: `string | Buffer | Uint8Array`. */
export function bytesOrString() {
  return make((input, path, errors) => {
    if (typeof input !== 'string' && !Buffer.isBuffer(input) && !(input instanceof Uint8Array)) {
      errors.push(`${path}: expected string, Buffer, or Uint8Array; got ${describe(input)}`);
    }
    return input;
  });
}

/** Callbacks: `keyGenerator`, `tokenFromRequest`, resolver functions, … */
export function func() {
  return make((input, path, errors) => {
    if (typeof input !== 'function') {
      errors.push(`${path}: expected function; got ${describe(input)}`);
    }
    return input;
  });
}

/**
 * Exactly `value` (compared with `Object.is`). Combine with `union`
 * for discriminated shapes.
 *
 * @param {unknown} value
 */
export function literal(value) {
  return make((input, path, errors) => {
    if (!Object.is(input, value)) {
      errors.push(`${path}: expected ${JSON.stringify(value)}; got ${describe(input)}`);
    }
    return input;
  });
}

export function nullish() {
  return make((input, path, errors) => {
    if (input !== null && input !== undefined) {
      errors.push(`${path}: expected null or undefined; got ${describe(input)}`);
    }
    return input;
  });
}

export function instanceOf(ctor) {
  return make((input, path, errors) => {
    if (!(input instanceof ctor)) {
      errors.push(`${path}: expected instance of ${ctor.name}; got ${describe(input)}`);
    }
    return input;
  });
}

export function regexp() {
  return instanceOf(RegExp);
}

// combinators

/**
 * @param {Record<string, Validator>} shape
 * @param {{ unknownKeys?: 'strip' | 'reject' }} [opts]
 *   `'strip'` (default) silently drops keys not in `shape` — the
 *   historical behaviour. `'reject'` errors on them; use it for
 *   boot-time config so a typo'd option key fails loudly instead of
 *   being ignored.
 */
export function object(shape, opts) {
  const unknownKeys = opts?.unknownKeys ?? 'strip';
  return make((input, path, errors) => {
    if (input == null || typeof input !== 'object' || Array.isArray(input)) {
      errors.push(`${path}: expected object; got ${describe(input)}`);
      return input;
    }
    if (unknownKeys === 'reject') {
      const extra = Object.keys(input).filter(k => !Object.hasOwn(shape, k));
      if (extra.length > 0) {
        errors.push(
          `${path}: unknown key${extra.length > 1 ? 's' : ''} ${extra.map(k => JSON.stringify(k)).join(', ')} — known keys: ${Object.keys(shape).join(', ')}`,
        );
      }
    }
    const out = {};
    for (const key of Object.keys(shape)) {
      const child = shape[key].safeParse(input[key], `${path}.${key}`);
      if (child.ok) {
        out[key] = child.value;
      } else {
        errors.push(...child.errors);
      }
    }
    return out;
  });
}

/**
 * String-keyed map with uniformly-typed values (header overrides,
 * label maps, …). Rejects arrays; prototype-polluting keys
 * (`__proto__`, `constructor`, `prototype`) are always rejected.
 *
 * @param {Validator} valueSchema
 */
export function record(valueSchema) {
  const banned = new Set(['__proto__', 'constructor', 'prototype']);
  return make((input, path, errors) => {
    if (input == null || typeof input !== 'object' || Array.isArray(input)) {
      errors.push(`${path}: expected object; got ${describe(input)}`);
      return input;
    }
    /** @type {Record<string, unknown>} */
    const out = Object.create(null);
    for (const key of Object.keys(input)) {
      if (banned.has(key)) {
        errors.push(`${path}: key ${JSON.stringify(key)} is not allowed`);
        continue;
      }
      const child = valueSchema.safeParse(input[key], `${path}.${key}`);
      if (child.ok) {
        out[key] = child.value;
      } else {
        errors.push(...child.errors);
      }
    }
    return out;
  });
}

export function array(itemSchema) {
  return make((input, path, errors) => {
    if (!Array.isArray(input)) {
      errors.push(`${path}: expected array; got ${describe(input)}`);
      return input;
    }
    const out = [];
    for (let i = 0; i < input.length; i++) {
      const child = itemSchema.safeParse(input[i], `${path}[${i}]`);
      if (child.ok) {
        out.push(child.value);
      } else {
        errors.push(...child.errors);
      }
    }
    return out;
  });
}

export function oneOf(values) {
  const set = new Set(values);
  return make((input, path, errors) => {
    if (!set.has(input)) {
      errors.push(`${path}: expected one of ${JSON.stringify(values)}; got ${describe(input)}`);
    }
    return input;
  });
}

export function union(...schemas) {
  return make((input, path, errors) => {
    const collected = [];
    for (const schema of schemas) {
      const r = schema.safeParse(input, path);
      if (r.ok) {
        return r.value;
      }
      collected.push(...r.errors);
    }
    errors.push(`${path}: no branch of union matched — ${collected.join(' | ')}`);
    return input;
  });
}

export function optional(schema) {
  return make((input, path, errors) => {
    if (input === undefined) {
      return undefined;
    }
    const r = schema.safeParse(input, path);
    if (r.ok) {
      return r.value;
    }
    errors.push(...r.errors);
    return input;
  });
}

/**
 * `undefined` → `defaultValue` (returned as-is, not validated);
 * anything else validates against `schema`. Lets a config schema
 * carry its own defaults instead of `options.x ?? DEFAULT` ladders at
 * every call site.
 *
 * @param {Validator} schema
 * @param {unknown} defaultValue
 */
export function withDefault(schema, defaultValue) {
  return make((input, path, errors) => {
    if (input === undefined) {
      return defaultValue;
    }
    const r = schema.safeParse(input, path);
    if (r.ok) {
      return r.value;
    }
    errors.push(...r.errors);
    return input;
  });
}

export function nullable(schema) {
  return make((input, path, errors) => {
    if (input === null) {
      return null;
    }
    const r = schema.safeParse(input, path);
    if (r.ok) {
      return r.value;
    }
    errors.push(...r.errors);
    return input;
  });
}

export function custom(predicate, message) {
  return make((input, path, errors) => {
    let ok;
    try {
      ok = predicate(input);
    } catch (err) {
      errors.push(`${path}: ${message} (${err instanceof Error ? err.message : String(err)})`);
      return input;
    }
    if (!ok) {
      errors.push(`${path}: ${message}; got ${describe(input)}`);
    }
    return input;
  });
}

// domain-specific shortcuts

const DURATION_RE = /^\s*-?\d+(?:\.\d+)?\s*[a-z]*\s*$/i;

/**
 * Accepts the same input shape as `parseDuration` from `time/duration.js`:
 * a number (interpreted as seconds by the parser) or a duration string
 * like `'15m'`. Does *not* invoke the parser — the schema only checks
 * shape; parsing runs downstream.
 */
export function duration() {
  return union(
    number(),
    string().refine(v => DURATION_RE.test(v), 'not a duration string'),
  );
}

// helpers

/**
 * @param {number} input
 * @param {string} path
 * @param {string[]} errors
 * @param {{ min?: number, max?: number }} [opts]
 */
function rangeCheck(input, path, errors, opts) {
  if (opts?.min !== undefined && input < opts.min) {
    errors.push(`${path}: expected ≥ ${opts.min}; got ${input}`);
  }
  if (opts?.max !== undefined && input > opts.max) {
    errors.push(`${path}: expected ≤ ${opts.max}; got ${input}`);
  }
}

function describe(value) {
  if (value === null) {
    return 'null';
  }
  if (value === undefined) {
    return 'undefined';
  }
  if (Array.isArray(value)) {
    return `array(len=${value.length})`;
  }
  if (typeof value === 'object') {
    return 'object';
  }
  if (typeof value === 'string') {
    const shown = value.length > 40 ? value.slice(0, 40) + '…' : value;
    return JSON.stringify(shown);
  }
  return `${typeof value}(${String(value)})`;
}
