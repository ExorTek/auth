import { SecurityError, ErrorCode } from '../internal/errors.js';
import { invalidArgument } from '../internal/guards.js';

/**
 * @typedef {string | RegExp} OriginMatcher
 */

/**
 * @typedef {object} CorsOptions
 * @property {boolean
 *   | OriginMatcher
 *   | Array<OriginMatcher>
 *   | ((origin: string | undefined) => boolean | Promise<boolean>)
 * } [origin=true]
 *   Which origins are allowed to make cross-origin requests.
 *   - `true`  → reflect any origin (echoes back the request's `Origin`).
 *   - `false` → CORS disabled; every cross-origin request is denied.
 *   - string  → exact match against the request's `Origin`.
 *   - RegExp  → pattern match.
 *   - Array   → any-of match against the entries.
 *   - Function → sync or async predicate; return true (or resolve to true) to allow.
 *     When the predicate is async, `check()` returns a Promise<CorsDecision>;
 *     for sync predicates it stays sync so consumers pay no async cost.
 * @property {string[] | string} [methods]
 *   Comma-separated string or array. Default:
 *   `['GET','HEAD','PUT','PATCH','POST','DELETE']`. Sent as
 *   `Access-Control-Allow-Methods` on preflight only.
 * @property {string[] | string | true} [allowedHeaders]
 *   Headers the browser may include on the actual request. Default `true` =
 *   echo the request's `Access-Control-Request-Headers`. Sent on preflight.
 * @property {string[] | string} [exposedHeaders]
 *   Response headers the browser may read via `getResponseHeader()`. Sent
 *   on the actual response.
 * @property {boolean} [credentials=false]
 *   When true, sets `Access-Control-Allow-Credentials: true`. Requires an
 *   exact-echoed origin — cannot be combined with the `*` wildcard.
 * @property {number} [maxAge]
 *   Seconds the browser may cache the preflight decision. Sent on preflight.
 * @property {number} [optionsSuccessStatus=204]
 *   HTTP status to end a preflight response with. Some legacy setups need
 *   200 instead — Chrome accepts either.
 */

/**
 * @typedef {object} CorsInput
 * @property {string} method                 Request method (e.g. 'GET', 'OPTIONS').
 * @property {string | undefined} origin     Value of the request's `Origin` header.
 * @property {string} [requestMethod]        `Access-Control-Request-Method` on preflight.
 * @property {string} [requestHeaders]       `Access-Control-Request-Headers` on preflight.
 */

/**
 * @typedef {object} CorsDecision
 * @property {Record<string, string>} headers
 *   CORS response headers to merge onto the response.
 * @property {boolean} allowed               Origin passed the policy check.
 * @property {boolean} preflight             Request was an OPTIONS preflight.
 * @property {number} [status]               Suggested response status for preflight.
 */

const DEFAULT_METHODS = ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE'];

function toList(v) {
  if (v === undefined || v === null) {
    return null;
  }
  if (Array.isArray(v)) {
    return v;
  }
  if (typeof v === 'string') {
    return v
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
  }
  return null;
}

function compileOriginCheck(origin) {
  if (origin === undefined || origin === true) {
    return () => true;
  }
  if (origin === false) {
    return () => false;
  }
  if (typeof origin === 'function') {
    return origin;
  }
  const matchers = Array.isArray(origin) ? origin : [origin];
  return incoming => {
    if (!incoming) {
      return false;
    }
    for (const m of matchers) {
      if (typeof m === 'string' && m === incoming) {
        return true;
      }
      if (m instanceof RegExp && m.test(incoming)) {
        return true;
      }
    }
    return false;
  };
}

function assertOptions(options) {
  if (options.credentials === true) {
    if (options.origin === true || options.origin === undefined) {
      throw new SecurityError(
        ErrorCode.INVALID_ARGUMENT,
        'cors: `credentials: true` requires an explicit allowlist for `origin` — you cannot combine credentials with `*` / reflect-any-origin (browsers reject it).',
      );
    }
  }
  if (options.maxAge !== undefined) {
    if (!Number.isFinite(options.maxAge) || options.maxAge < 0) {
      throw new SecurityError(
        ErrorCode.INVALID_ARGUMENT,
        `cors: maxAge must be a non-negative number of seconds; got ${options.maxAge}`,
      );
    }
  }
  if (options.optionsSuccessStatus !== undefined) {
    const s = options.optionsSuccessStatus;
    if (!Number.isInteger(s) || s < 200 || s > 299) {
      throw invalidArgument(`cors.options.optionsSuccessStatus must be a 2xx integer; got ${s}`);
    }
  }
}

/**
 * Build a CORS decision function.
 *
 *   const check = cors({ origin: ['https://app.example.com'], credentials: true })
 *
 *   // In your framework middleware:
 *   const d = check({
 *     method: req.method,
 *     origin: req.headers.origin,
 *     requestMethod: req.headers['access-control-request-method'],
 *     requestHeaders: req.headers['access-control-request-headers'],
 *   })
 *   for (const [k, v] of Object.entries(d.headers)) res.setHeader(k, v)
 *   if (d.preflight) { res.statusCode = d.status; res.end(); return }
 *   if (!d.allowed) { res.statusCode = 403; res.end(); return }
 *
 * The returned function is pure — no state, safe to reuse across requests
 * and across workers. When the configured `origin` predicate is async
 * (returns a Promise), `check()` returns `Promise<CorsDecision>`; for sync
 * predicates it stays synchronous so hot paths don't pay a needless await.
 *
 * @param {CorsOptions} [options]
 * @returns {(input: CorsInput) => CorsDecision | Promise<CorsDecision>}
 */
export function cors(options = {}) {
  assertOptions(options);
  const isAllowed = compileOriginCheck(options.origin);
  const methods = toList(options.methods) ?? DEFAULT_METHODS;
  const exposedHeaders = toList(options.exposedHeaders);
  const allowedHeadersOpt = options.allowedHeaders;
  const staticAllowedHeaders = allowedHeadersOpt === true ? null : toList(allowedHeadersOpt);
  const credentials = options.credentials === true;
  const maxAge = options.maxAge;
  const preflightStatus = options.optionsSuccessStatus ?? 204;
  const reflectAny = options.origin === true || options.origin === undefined;

  // Assemble the response given a resolved allow/deny decision. Kept as
  // an inner closure so both the sync path and the async .then() path can
  // share the header-building logic without duplicating it.
  function buildDecision(allowed, input, preflight) {
    /** @type {Record<string, string>} */
    const headers = {};
    if (!allowed) {
      return {
        headers,
        allowed: false,
        preflight,
        status: preflight ? preflightStatus : undefined,
      };
    }
    // Spec-safe fast path: only send `*` when we're reflecting-any AND
    // credentials are off. Everything else echoes the incoming origin so
    // the Allow-Credentials contract holds.
    const allowOriginValue = reflectAny && !credentials ? '*' : input.origin;
    if (allowOriginValue) {
      headers['Access-Control-Allow-Origin'] = allowOriginValue;
    }
    if (allowOriginValue !== '*') {
      headers.Vary = 'Origin';
    }
    if (credentials) {
      headers['Access-Control-Allow-Credentials'] = 'true';
    }
    if (preflight) {
      headers['Access-Control-Allow-Methods'] = methods.join(', ');
      const echoed = staticAllowedHeaders ? staticAllowedHeaders.join(', ') : (input.requestHeaders ?? '');
      if (echoed) {
        headers['Access-Control-Allow-Headers'] = echoed;
        if (!staticAllowedHeaders) {
          headers.Vary = headers.Vary
            ? `${headers.Vary}, Access-Control-Request-Headers`
            : 'Access-Control-Request-Headers';
        }
      }
      if (typeof maxAge === 'number') {
        headers['Access-Control-Max-Age'] = String(Math.floor(maxAge));
      }
      return { headers, allowed: true, preflight: true, status: preflightStatus };
    }
    if (exposedHeaders && exposedHeaders.length) {
      headers['Access-Control-Expose-Headers'] = exposedHeaders.join(', ');
    }
    return { headers, allowed: true, preflight: false };
  }

  return function checkCors(input) {
    const method = (input.method || '').toUpperCase();
    const preflight = method === 'OPTIONS' && typeof input.requestMethod === 'string';
    const verdict = isAllowed(input.origin);
    // Detect thenables (native Promise, custom async predicate wrappers).
    // Keeping the sync path allocation-free matters — this is called on
    // every request.
    if (verdict && typeof verdict.then === 'function') {
      return verdict.then(ok => buildDecision(Boolean(ok), input, preflight));
    }
    return buildDecision(Boolean(verdict), input, preflight);
  };
}
