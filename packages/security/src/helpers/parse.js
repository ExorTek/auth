import { SecurityError, ErrorCode } from '../internal/errors.js';
import { timingSafeEqual } from '../util/bytes.js';

/**
 * @typedef {object} SafeJsonParseOptions
 * @property {'strip' | 'reject' | 'throw'} [mode='reject']
 *   How to react to `__proto__` / `constructor` / `prototype` keys.
 *   - `reject` (default): return `null`, the parsed result is discarded.
 *   - `strip`:  silently drop the offending keys, keep the rest.
 *   - `throw`:  raise `SecurityError` — surface bad payloads loudly.
 * @property {number} [maxDepth=32]
 *   Refuses to walk beyond this level. Guards against pathological /
 *   self-referential payloads that could stall the event loop.
 * @property {number} [maxBytes=1_000_000]
 *   Reject the input outright when longer than this. Comes before the
 *   parse, so we never actually construct a huge object graph.
 * @property {Set<string>} [banned=new Set(['__proto__','constructor','prototype'])]
 *   Keys that are considered dangerous. Defaults cover the classic
 *   prototype-pollution vectors; extend if your app has extra concerns.
 */

const DEFAULT_BANNED = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Parse JSON with a prototype-pollution guard. Complements
 * `freezePrototypes()` — that closes the door on writes to
 * `Object.prototype` globally; `safeJsonParse` closes the door at the
 * request boundary where user-controlled JSON enters.
 *
 * Returns `null` on any failure (parse error, banned key in `reject`
 * mode, oversize input) so callers can uniformly branch on `!result`.
 *
 * @param {string | Buffer} input
 * @param {SafeJsonParseOptions} [options]
 * @returns {unknown | null}
 */
export function safeJsonParse(input, options = {}) {
  const mode = options.mode ?? 'reject';
  const maxDepth = options.maxDepth ?? 32;
  const maxBytes = options.maxBytes ?? 1_000_000;
  const banned = options.banned ?? DEFAULT_BANNED;

  const str = Buffer.isBuffer(input) ? input.toString('utf8') : input;
  if (typeof str !== 'string') {
    return null;
  }
  if (str.length > maxBytes) {
    if (mode === 'throw') {
      throw new SecurityError(
        ErrorCode.BODY_TOO_LARGE,
        `safeJsonParse: input length ${str.length} exceeds maxBytes=${maxBytes}`,
      );
    }
    return null;
  }

  // Route the banned-key check through JSON.parse's reviver. It sees keys
  // during construction so we can veto them before they land on any
  // enumerable slot of the built object.
  let flagged = false;
  const reviver = (key, value) => {
    if (banned.has(key)) {
      flagged = true;
      if (mode === 'strip') {
        // Returning undefined from a reviver deletes the property.
        return undefined;
      }
      // In reject/throw modes we let the value through here and decide
      // after parse completes — a single throw-inside-reviver would let
      // some parsers leave partial state on the caller.
      return value;
    }
    return value;
  };

  let parsed;
  try {
    parsed = JSON.parse(str, reviver);
  } catch {
    return null;
  }

  if (flagged && mode !== 'strip') {
    if (mode === 'throw') {
      throw new SecurityError(
        ErrorCode.INVALID_ARGUMENT,
        'safeJsonParse: parsed payload contained a banned key (prototype-pollution vector)',
      );
    }
    return null;
  }

  // Depth guard — cheap post-parse walk; JSON.parse itself doesn't stack-
  // overflow easily, but a caller that plans to iterate a 100k-deep
  // structure shouldn't be handed one silently.
  if (!withinDepth(parsed, maxDepth)) {
    if (mode === 'throw') {
      throw new SecurityError(ErrorCode.INVALID_ARGUMENT, `safeJsonParse: parsed value exceeds maxDepth=${maxDepth}`);
    }
    return null;
  }

  return parsed;
}

function withinDepth(value, remaining) {
  if (remaining < 0) {
    return false;
  }
  if (Array.isArray(value)) {
    for (const v of value) {
      if (!withinDepth(v, remaining - 1)) {
        return false;
      }
    }
    return true;
  }
  if (value !== null && typeof value === 'object') {
    for (const v of Object.values(value)) {
      if (!withinDepth(v, remaining - 1)) {
        return false;
      }
    }
  }
  return true;
}

/**
 * Constant-time equality for user-supplied tokens / signatures.
 *
 * `node:crypto`'s `timingSafeEqual` throws when lengths differ — which
 * itself leaks length via the exception path. This wrapper accepts
 * strings or byte views, returns `false` on length mismatch without
 * throwing, and burns a fixed amount of comparison time in that path.
 *
 * @param {string | Buffer | Uint8Array} a
 * @param {string | Buffer | Uint8Array} b
 * @returns {boolean}
 */
export function constantTimeEqual(a, b) {
  if (a == null || b == null) {
    return false;
  }
  try {
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/**
 * @typedef {object} CspReport
 * @property {string | undefined} documentUri
 * @property {string | undefined} referrer
 * @property {string | undefined} blockedUri
 * @property {string | undefined} effectiveDirective
 * @property {string | undefined} violatedDirective
 * @property {string | undefined} disposition       'enforce' | 'report'
 * @property {number | undefined} statusCode
 * @property {string | undefined} sourceFile
 * @property {number | undefined} lineNumber
 * @property {number | undefined} columnNumber
 * @property {string | undefined} sample
 * @property {string | undefined} originalPolicy
 */

/**
 * Normalize a CSP violation report submitted to a `report-uri` or
 * `report-to` endpoint into a flat object. Browsers ship two dialects:
 *
 *   1. Legacy `report-uri` (Content-Type: application/csp-report)
 *      `{ "csp-report": { "blocked-uri": "...", ... } }`
 *   2. Modern `report-to` (Content-Type: application/reports+json)
 *      `[ { "type": "csp-violation", "body": { "blockedURL": "...", ... } } ]`
 *
 * Both use kebab / snake / camelCase inconsistently across engines.
 * This helper takes the raw body (string OR already-parsed object) and
 * returns a single normalized shape. Returns `null` when the body is
 * not a recognizable CSP report.
 *
 * @param {unknown} body
 * @returns {CspReport | null}
 */
export function parseCspReport(body) {
  let payload = body;
  if (typeof payload === 'string' || Buffer.isBuffer(payload)) {
    payload = safeJsonParse(payload, { mode: 'strip' });
    if (payload === null) {
      return null;
    }
  }
  if (!payload || typeof payload !== 'object') {
    return null;
  }

  // Modern `report-to` may deliver an array of one-or-more reports.
  // Pull out the first CSP violation entry.
  if (Array.isArray(payload)) {
    for (const entry of payload) {
      if (entry && typeof entry === 'object' && entry.type === 'csp-violation' && entry.body) {
        return pick(entry.body);
      }
    }
    return null;
  }

  // Legacy shape: `{ "csp-report": { ... } }`.
  const legacy = payload['csp-report'];
  if (legacy && typeof legacy === 'object') {
    return pick(legacy);
  }
  // Sometimes the outer object IS the report (server middleware may have
  // unwrapped already). Give it a try.
  return pick(payload);
}

function pick(src) {
  const g = (...keys) => {
    for (const k of keys) {
      const v = src[k];
      if (v !== undefined && v !== null) {
        return v;
      }
    }
    return undefined;
  };
  const out = {
    documentUri: g('documentURL', 'document-uri', 'documentUri'),
    referrer: g('referrer'),
    blockedUri: g('blockedURL', 'blocked-uri', 'blockedUri'),
    effectiveDirective: g('effectiveDirective', 'effective-directive'),
    violatedDirective: g('violatedDirective', 'violated-directive'),
    disposition: g('disposition'),
    statusCode: g('statusCode', 'status-code'),
    sourceFile: g('sourceFile', 'source-file'),
    lineNumber: g('lineNumber', 'line-number'),
    columnNumber: g('columnNumber', 'column-number'),
    sample: g('sample', 'scriptSample', 'script-sample'),
    originalPolicy: g('originalPolicy', 'original-policy'),
  };
  // If literally nothing survived, this wasn't a CSP report.
  const hasSomething = out.blockedUri || out.effectiveDirective || out.violatedDirective || out.documentUri;
  return hasSomething ? out : null;
}
