/**
 * Adapter-kit core for `@exortek/apikey` middleware.
 *
 * The framework-neutral logic lives here. The Express and Fastify
 * adapters (`middleware/express.js`, `middleware/fastify.js`) are
 * thin translators: request → `AdapterContext`, then hand off to
 * `runApiKey`, then translate the returned `AdapterResult` back into
 * the framework's own reply / next call.
 *
 * External integrators writing their own framework binding only need
 * to implement the two-line translation — every auth decision,
 * error-code, and header choice already lives here.
 */

import { isFunction, isString, isUndefined } from '@exortek/shared/predicates';

import { invalidArgument } from '../internal/guards.js';
import { verifyApiKey } from '../index.js';

/**
 * @typedef {object} AdapterContext
 * @property {(name: string) => string | undefined} getHeader
 * @property {string} [method]
 * @property {string} [ip]
 * @property {Record<string, unknown>} [query]
 */

/**
 * @typedef {object} ApiKeyMiddlewareOptions
 * @property {import('../index.js').ApiKeyStore} store
 * @property {(Buffer | Uint8Array | string)[]} [peppers]
 * @property {string[]} [requiredScopes]
 * @property {string} [expectedPrefix]
 * @property {boolean} [updateLastUsed=false]
 * @property {string} [headerName='authorization']
 *   Case-insensitive. The default reads `Authorization: Bearer <key>`;
 *   a `x-api-key` config reads `X-API-Key: <key>` directly.
 * @property {'bearer' | 'raw'} [scheme='bearer']
 *   `'bearer'` expects `Bearer <key>`; `'raw'` uses the header value as-is.
 * @property {boolean} [allowQueryParam=false]
 *   When true, falls back to `?api_key=<key>` if no matching header is
 *   found. Discouraged because query strings leak into access logs and
 *   referer headers — off by default.
 * @property {string} [queryParamName='api_key']
 * @property {string} [attach='apiKey']
 *   Property name attached to the request object on success.
 * @property {(ctx: AdapterContext) => string | undefined} [tokenFromRequest]
 *   Override the default extraction entirely.
 */

/**
 * @typedef {{
 *   verifyResult: import('../index.js').VerifyApiKeyResult,
 *   response?: { status: number, body: { error: string, reason?: string } }
 * }} AdapterResult
 */

const DEFAULT_HEADER = 'authorization';
const DEFAULT_QUERY = 'api_key';

/**
 * Normalize + validate middleware options. Throws `ApiKeyError` on
 * misconfig so the mistake surfaces at boot, not per-request.
 *
 * @param {ApiKeyMiddlewareOptions} options
 */
export function normalizeOptions(options) {
  if (!options || typeof options !== 'object') {
    throw invalidArgument('apiKey middleware options must be an object');
  }
  if (!options.store) {
    throw invalidArgument('apiKey middleware options.store is required');
  }
  if (!isUndefined(options.tokenFromRequest) && !isFunction(options.tokenFromRequest)) {
    throw invalidArgument('apiKey middleware options.tokenFromRequest must be a function when provided');
  }
  const attach = options.attach ?? 'apiKey';
  if (!isString(attach) || attach.length === 0) {
    throw invalidArgument('apiKey middleware options.attach must be a non-empty string');
  }
  return {
    store: options.store,
    peppers: options.peppers,
    requiredScopes: options.requiredScopes,
    expectedPrefix: options.expectedPrefix,
    updateLastUsed: options.updateLastUsed === true,
    headerName: (options.headerName ?? DEFAULT_HEADER).toLowerCase(),
    scheme: options.scheme ?? 'bearer',
    allowQueryParam: options.allowQueryParam === true,
    queryParamName: options.queryParamName ?? DEFAULT_QUERY,
    attach,
    tokenFromRequest: options.tokenFromRequest,
  };
}

/**
 * Extract the raw key from a request context per the configured
 * scheme. Returns `null` when no candidate was found (the caller then
 * responds with 401 `missing_key`).
 *
 * @param {AdapterContext} ctx
 * @param {ReturnType<typeof normalizeOptions>} config
 * @returns {string | null}
 */
export function extractKey(ctx, config) {
  if (config.tokenFromRequest) {
    const custom = config.tokenFromRequest(ctx);
    return isString(custom) && custom.length > 0 ? custom : null;
  }
  const raw = ctx.getHeader(config.headerName);
  if (isString(raw) && raw.length > 0) {
    if (config.scheme === 'bearer') {
      const m = /^bearer\s+(.+)$/i.exec(raw.trim());
      if (m) {
        return m[1].trim();
      }
    } else {
      return raw.trim();
    }
  }
  if (config.allowQueryParam && ctx.query) {
    const q = ctx.query[config.queryParamName];
    if (isString(q) && q.length > 0) {
      return q;
    }
  }
  return null;
}

/**
 * Run the verify against the request. Returns a discriminated result:
 * on success the caller attaches `verifyResult` to the request and
 * proceeds; on failure the caller sends the returned `response`.
 *
 * @param {AdapterContext} ctx
 * @param {ReturnType<typeof normalizeOptions>} config
 * @returns {Promise<AdapterResult>}
 */
export async function runApiKey(ctx, config) {
  const raw = extractKey(ctx, config);
  if (!raw) {
    return {
      verifyResult: { valid: false, reason: 'malformed' },
      response: { status: 401, body: { error: 'missing_api_key' } },
    };
  }
  const verifyResult = await verifyApiKey(raw, {
    store: config.store,
    peppers: config.peppers,
    requiredScopes: config.requiredScopes,
    expectedPrefix: config.expectedPrefix,
    updateLastUsed: config.updateLastUsed,
  });
  if (!verifyResult.valid) {
    const status = _statusFor(verifyResult.reason);
    return {
      verifyResult,
      response: { status, body: { error: 'invalid_api_key', reason: verifyResult.reason } },
    };
  }
  return { verifyResult };
}

function _statusFor(reason) {
  switch (reason) {
    case 'missing_scope':
      return 403;
    case 'store_unavailable':
      return 503;
    default:
      return 401;
  }
}
