import { randomBytes } from 'node:crypto';
import {
  buildCsp,
  buildHsts,
  buildContentTypeOptions,
  buildDnsPrefetchControl,
  buildDownloadOptions,
  buildPermittedCrossDomain,
  buildOriginAgentCluster,
  buildXssProtection,
  buildCoop,
  buildCoep,
  buildCorp,
  buildReferrerPolicy,
  buildFrameguard,
  buildPermissionsPolicy,
} from './policies.js';

/**
 * CSP directive map. Keys are camelCase; values are arrays of source
 * expressions. A value of `false` removes a default-provided directive.
 * @typedef {Record<string, string[] | false>} CspDirectives
 */

/**
 * @typedef {object} CspOptions
 * @property {CspDirectives} [directives]
 * @property {boolean} [useDefaults=true]
 * @property {boolean} [reportOnly=false]
 */

/**
 * @typedef {object} HstsOptions
 * @property {number} [maxAge=15552000]     Seconds. Default 180 days.
 * @property {boolean} [includeSubDomains=true]
 * @property {boolean} [preload=false]      Requires maxAge >= 1y + includeSubDomains.
 */

/**
 * @typedef {'DENY' | 'SAMEORIGIN' | { action: 'DENY' | 'SAMEORIGIN' }} FrameguardOptions
 */

/**
 * @typedef {object} PermissionsPolicyOptions
 * @property {Record<string, string[]>} [features]
 */

/**
 * A static-value policy option:
 *   true → default value, false → skip,
 *   string / { value } → verbatim override.
 * @typedef {boolean | string | { value: string } | undefined} StaticHeaderOption
 */

/**
 * @typedef {object} HeadersOptions
 * @property {boolean | CspOptions} [contentSecurityPolicy]
 * @property {boolean | HstsOptions} [hsts]
 * @property {boolean | HstsOptions} [strictTransportSecurity] Alias of `hsts`.
 * @property {StaticHeaderOption} [contentTypeOptions]
 * @property {StaticHeaderOption} [dnsPrefetchControl]
 * @property {StaticHeaderOption} [downloadOptions]
 * @property {StaticHeaderOption} [permittedCrossDomainPolicies]
 * @property {StaticHeaderOption} [originAgentCluster]
 * @property {StaticHeaderOption} [xssProtection]
 * @property {StaticHeaderOption} [crossOriginOpenerPolicy]
 * @property {StaticHeaderOption} [crossOriginEmbedderPolicy]
 * @property {StaticHeaderOption} [crossOriginResourcePolicy]
 * @property {StaticHeaderOption} [referrerPolicy]
 * @property {boolean | FrameguardOptions} [frameguard]
 * @property {boolean | PermissionsPolicyOptions} [permissionsPolicy]
 */

/**
 * Build a map of HTTP security headers.
 *
 * `headers()` with no options ships secure-by-default headers suitable for
 * an HTTPS API or SSR app. Each policy can be opted out with `false` or
 * customized via its own options object — see the individual `build*`
 * functions in `./policies.js` for supported shapes.
 *
 *   import { headers } from '@exortek/security'
 *
 *   const map = headers({
 *     hsts: { maxAge: 31536000, preload: true },
 *     contentSecurityPolicy: {
 *       directives: { scriptSrc: ["'self'", "https://cdn.example.com"] },
 *     },
 *     crossOriginEmbedderPolicy: false,  // COEP breaks many embeds
 *     frameguard: 'SAMEORIGIN',
 *   })
 *   // → { 'Content-Security-Policy': "...", 'Strict-Transport-Security': "...", ... }
 *
 * For per-request CSP nonces, use `cspNonce()` and template the resulting
 * string into `directives.scriptSrc` before calling `headers()`.
 *
 * Returns a plain `{ [name]: value }` object. Framework middleware iterates
 * and calls the framework's response setter; consumers can also assign the
 * map directly onto a Response.
 *
 * @param {HeadersOptions} [options]
 * @returns {Record<string, string>}
 */
export function headers(options = {}) {
  const results = [
    buildCsp(options.contentSecurityPolicy),
    buildHsts(options.hsts ?? options.strictTransportSecurity),
    buildContentTypeOptions(options.contentTypeOptions ?? true),
    buildDnsPrefetchControl(options.dnsPrefetchControl ?? true),
    buildDownloadOptions(options.downloadOptions ?? true),
    buildPermittedCrossDomain(options.permittedCrossDomainPolicies ?? true),
    buildOriginAgentCluster(options.originAgentCluster ?? true),
    buildXssProtection(options.xssProtection ?? true),
    buildCoop(options.crossOriginOpenerPolicy ?? true),
    buildCoep(options.crossOriginEmbedderPolicy ?? true),
    buildCorp(options.crossOriginResourcePolicy ?? true),
    buildReferrerPolicy(options.referrerPolicy ?? true),
    buildFrameguard(options.frameguard ?? true),
    buildPermissionsPolicy(options.permissionsPolicy),
  ];
  const out = {};
  for (const r of results) {
    if (r) {
      out[r.name] = r.value;
    }
  }
  return out;
}

/**
 * Generate a fresh CSP nonce.
 *
 * A nonce is a random per-response value; embed the SAME nonce in your CSP
 * `script-src` (as `'nonce-<value>'`) and on every inline `<script nonce>`
 * so the browser executes only whitelisted inline scripts. Regenerate on
 * every response — a reused nonce defeats the purpose.
 *
 * Default 16 bytes (128 bits) → base64 → 22 chars, MDN's recommended size.
 *
 * @param {number} [bytes=16]
 * @returns {string} base64-encoded nonce
 */
export function cspNonce(bytes = 16) {
  if (!Number.isInteger(bytes) || bytes < 8 || bytes > 64) {
    throw new TypeError(`cspNonce: bytes must be an integer between 8 and 64; got ${bytes}`);
  }
  return randomBytes(bytes).toString('base64');
}
