import { resolve, sep } from 'node:path';

import { isArray, isString } from '@exortek/shared/predicates';

import { SecurityError, ErrorCode } from '../internal/errors.js';
import { assertNonEmptyString, assertString } from '../internal/guards.js';

/**
 * @typedef {object} SanitizeBodyOptions
 * @property {'strip' | 'reject'} [mode='strip']
 *   `strip` silently removes suspicious keys; `reject` throws
 *   SecurityError. Use `reject` on trusted APIs where a bad shape
 *   indicates a bug (or attack) worth alerting on.
 * @property {RegExp} [suspicious=/^\$|\./]
 *   Test applied to each own-property key. Default catches MongoDB
 *   operators (`$gt`, `$where`, …) and dotted keys (`a.b.c`) that
 *   Mongoose interprets as nested paths.
 * @property {number} [maxDepth=8]
 *   Recursion guard against pathological / self-referential payloads.
 *
 * Regardless of `suspicious`, the prototype-pollution keys `__proto__`,
 * `constructor`, and `prototype` are ALWAYS treated as dangerous — they
 * cannot be re-enabled by narrowing the regex.
 */

const PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Defensive NoSQL / operator-injection sanitizer. Walks the value tree
 * and either drops or rejects keys that look like operators or nested
 * paths. Idempotent, allocates a new object rather than mutating input.
 *
 * Also unconditionally strips the prototype-pollution vectors `__proto__`,
 * `constructor`, and `prototype`, and writes output keys as own properties
 * (never via the prototype chain) so a `__proto__` key in the input can't
 * shift the returned object's prototype.
 *
 * @param {unknown} input
 * @param {SanitizeBodyOptions} [options]
 * @returns {unknown}
 */
export function sanitizeBody(input, options = {}) {
  const mode = options.mode ?? 'strip';
  const suspicious = options.suspicious ?? /^\$|\./;
  const maxDepth = options.maxDepth ?? 8;

  function walk(value, depth) {
    if (depth > maxDepth) {
      // A malicious payload can trivially self-reference; deep enough is
      // "give up" territory. Reject rather than silently truncate — a
      // client that hits this needs to know.
      throw new SecurityError(
        ErrorCode.INVALID_ARGUMENT,
        `sanitizeBody: nesting exceeds ${maxDepth} — refusing to walk further`,
      );
    }
    if (isArray(value)) {
      return value.map(v => walk(v, depth + 1));
    }
    if (value === null || typeof value !== 'object') {
      return value;
    }
    /** @type {Record<string, unknown>} */
    const out = {};
    for (const key of Object.keys(value)) {
      if (PROTO_KEYS.has(key)) {
        if (mode === 'reject') {
          throw new SecurityError(
            ErrorCode.INVALID_ARGUMENT,
            `sanitizeBody: rejected prototype-pollution key '${key}'`,
          );
        }
        continue;
      }
      if (suspicious.test(key)) {
        if (mode === 'reject') {
          throw new SecurityError(
            ErrorCode.INVALID_ARGUMENT,
            `sanitizeBody: rejected key '${key}' matches the suspicious-key filter`,
          );
        }
        continue;
      }
      // Assign as an own property so a residual `__proto__`-like key can
      // never redefine `out`'s prototype via the assignment itself.
      Object.defineProperty(out, key, {
        value: walk(value[key], depth + 1),
        writable: true,
        enumerable: true,
        configurable: true,
      });
    }
    return out;
  }

  return walk(input, 0);
}

/**
 * @typedef {object} SanitizeParamsOptions
 * @property {'first' | 'last' | 'array'} [mode='first']
 *   How to collapse duplicate query keys.
 *     - `first` — take the earliest value (safest default; matches most
 *       server-side language runtimes).
 *     - `last`  — take the trailing value.
 *     - `array` — leave arrays as-is; caller handles ambiguity.
 * @property {number} [maxParams=1000]
 *   Reject payloads with more distinct keys than this — a soft DoS guard.
 */

/**
 * HTTP Parameter Pollution (HPP) sanitizer. Different runtimes disagree on
 * how to interpret `?x=1&x=2`; attackers exploit the divergence between
 * parser and business logic. This normalizes to a single value per key.
 *
 * @param {Record<string, unknown>} query    Parsed query object.
 * @param {SanitizeParamsOptions} [options]
 * @returns {Record<string, unknown>}
 */
export function sanitizeParams(query, options = {}) {
  const mode = options.mode ?? 'first';
  const maxParams = options.maxParams ?? 1000;

  if (query === null || typeof query !== 'object') {
    return {};
  }
  const keys = Object.keys(query);
  if (keys.length > maxParams) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `sanitizeParams: query contains ${keys.length} keys, exceeds maxParams=${maxParams}`,
    );
  }

  /** @type {Record<string, unknown>} */
  const out = {};
  for (const key of keys) {
    const v = query[key];
    if (!isArray(v)) {
      out[key] = v;
      continue;
    }
    if (mode === 'array') {
      out[key] = v;
    } else if (mode === 'last') {
      out[key] = v[v.length - 1];
    } else {
      out[key] = v[0];
    }
  }
  return out;
}

/**
 * Resolve a user-provided path segment(s) within a fixed base directory.
 * Guards against `..` traversal, absolute-path smuggling, and null-byte
 * tricks. Returns the fully-resolved absolute path when safe, or throws
 * SecurityError when the joined path escapes the base.
 *
 * @param {string} base                   Absolute base directory (trusted).
 * @param {...string} segments            User-controlled path pieces.
 * @returns {string}                      Absolute, canonicalized path.
 */
export function safeJoin(base, ...segments) {
  assertNonEmptyString(base, 'safeJoin.base');
  for (const seg of segments) {
    assertString(seg, 'safeJoin.segment');
    if (seg.indexOf('\0') !== -1) {
      // NUL bytes truncate paths in some C-level APIs; refuse outright.
      throw new SecurityError(ErrorCode.PATH_TRAVERSAL, 'safeJoin: NUL byte in segment');
    }
  }
  const resolvedBase = resolve(base);
  const joined = resolve(resolvedBase, ...segments);
  // Add a separator so `resolvedBase = /var/data` doesn't accept
  // `/var/data-secret/...`.
  if (joined !== resolvedBase && !joined.startsWith(resolvedBase + sep)) {
    throw new SecurityError(
      ErrorCode.PATH_TRAVERSAL,
      `safeJoin: resolved path '${joined}' escapes base '${resolvedBase}'`,
    );
  }
  return joined;
}

/**
 * @typedef {object} SanitizeFilenameOptions
 * @property {string} [replacement='_']   Replacement for illegal characters.
 * @property {number} [maxLength=255]     Cap the returned length.
 * @property {string} [fallback='file']   Returned when everything got stripped.
 */

const ILLEGAL_FILENAME_CHARS = /[<>:"/\\|?*\x00-\x1f]/g;
const RESERVED_WINDOWS_NAMES = new Set([
  'CON',
  'PRN',
  'AUX',
  'NUL',
  'COM1',
  'COM2',
  'COM3',
  'COM4',
  'COM5',
  'COM6',
  'COM7',
  'COM8',
  'COM9',
  'LPT1',
  'LPT2',
  'LPT3',
  'LPT4',
  'LPT5',
  'LPT6',
  'LPT7',
  'LPT8',
  'LPT9',
]);

/**
 * Normalize a user-supplied filename into something safe to write to disk
 * on Windows, macOS, and Linux. Strips path separators, control chars,
 * reserved Windows names, and leading/trailing dots.
 *
 * @param {unknown} input
 * @param {SanitizeFilenameOptions} [options]
 * @returns {string}
 */
export function sanitizeFilename(input, options = {}) {
  const replacement = options.replacement ?? '_';
  const maxLength = options.maxLength ?? 255;
  const fallback = options.fallback ?? 'file';

  let name = isString(input) ? input : String(input ?? '');
  // Never treat the input as a path — take the trailing component only.
  const lastSep = Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\'));
  if (lastSep >= 0) {
    name = name.slice(lastSep + 1);
  }
  name = name.replace(ILLEGAL_FILENAME_CHARS, replacement);
  // Strip leading dots (`.hidden`, `..`) and trailing spaces/dots — the
  // latter causes silent name changes on Windows.
  name = name.replace(/^\.+/, '').replace(/[ .]+$/, '');
  if (RESERVED_WINDOWS_NAMES.has(name.split('.')[0].toUpperCase())) {
    name = replacement + name;
  }
  if (name.length > maxLength) {
    name = name.slice(0, maxLength);
  }
  return name.length ? name : fallback;
}
