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

export function string() {
  return make((input, path, errors) => {
    if (typeof input !== 'string') {
      errors.push(`${path}: expected string; got ${describe(input)}`);
    }
    return input;
  });
}

export function number() {
  return make((input, path, errors) => {
    if (typeof input !== 'number' || !Number.isFinite(input)) {
      errors.push(`${path}: expected finite number; got ${describe(input)}`);
    }
    return input;
  });
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

export function object(shape) {
  return make((input, path, errors) => {
    if (input == null || typeof input !== 'object' || Array.isArray(input)) {
      errors.push(`${path}: expected object; got ${describe(input)}`);
      return input;
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
