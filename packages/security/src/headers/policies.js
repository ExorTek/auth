import { isArray, isObject, isString } from '@exortek/shared/predicates';

import { SecurityError, ErrorCode } from '../internal/errors.js';

// Content-Security-Policy
//
// CSP is a serialized set of directives: `directive src src; directive src`.
// Directive names use kebab-case on the wire but camelCase in options for
// ergonomics — `defaultSrc` ↔ `default-src`. Values are arrays of source
// expressions (self / origins / quoted keywords like 'unsafe-inline').

const CSP_DEFAULT_DIRECTIVES = Object.freeze({
  defaultSrc: ["'self'"],
  baseUri: ["'self'"],
  fontSrc: ["'self'", 'https:', 'data:'],
  formAction: ["'self'"],
  frameAncestors: ["'self'"],
  imgSrc: ["'self'", 'data:'],
  objectSrc: ["'none'"],
  scriptSrc: ["'self'"],
  scriptSrcAttr: ["'none'"],
  styleSrc: ["'self'", 'https:', "'unsafe-inline'"],
  upgradeInsecureRequests: [],
});

function kebab(camel) {
  return camel.replace(/[A-Z]/g, m => `-${m.toLowerCase()}`);
}

function assertDirectiveValue(value, name) {
  if (!isArray(value)) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `csp directive '${name}' must be an array of source expressions; got ${typeof value}`,
    );
  }
  for (const v of value) {
    if (typeof v !== 'string') {
      throw new SecurityError(
        ErrorCode.INVALID_ARGUMENT,
        `csp directive '${name}' entries must be strings; found ${typeof v}`,
      );
    }
    if (v.includes(';') || v.includes(',') || v.includes('\n')) {
      // Bare directive separators inside a value would silently break the
      // whole header. Reject at build time.
      throw new SecurityError(
        ErrorCode.INVALID_ARGUMENT,
        `csp source '${v}' contains an illegal delimiter (; , or newline)`,
      );
    }
  }
}

export function buildCsp(options) {
  if (options === false) {
    return null;
  }
  const opts = options === true || options === undefined ? {} : options;
  const useDefaults = opts.useDefaults !== false;
  const merged = useDefaults ? { ...CSP_DEFAULT_DIRECTIVES } : {};
  if (opts.directives) {
    for (const [name, value] of Object.entries(opts.directives)) {
      // `false` explicitly removes a default-provided directive; useful for
      // turning off e.g. upgrade-insecure-requests during local dev.
      if (value === false) {
        delete merged[name];
        continue;
      }
      assertDirectiveValue(value, name);
      merged[name] = value;
    }
  }
  const parts = [];
  for (const [name, value] of Object.entries(merged)) {
    const wire = kebab(name);
    parts.push(value.length === 0 ? wire : `${wire} ${value.join(' ')}`);
  }
  return {
    name: opts.reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy',
    value: parts.join('; '),
  };
}

// Strict-Transport-Security
//
// `max-age` is required. `preload` needs `includeSubDomains` and a minimum
// max-age of 31536000 (1y) to qualify for the browser preload list —
// warn (throw) if the caller opts in without meeting the criteria.

export function buildHsts(options) {
  if (options === false) {
    return null;
  }
  const opts = options === true || options === undefined ? {} : options;
  const maxAge = opts.maxAge ?? 15_552_000; // 180 days
  if (!Number.isFinite(maxAge) || maxAge < 0) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `hsts.maxAge must be a non-negative number of seconds; got ${maxAge}`,
    );
  }
  const parts = [`max-age=${Math.floor(maxAge)}`];
  if (opts.includeSubDomains !== false) {
    parts.push('includeSubDomains');
  }
  if (opts.preload) {
    if (maxAge < 31_536_000 || opts.includeSubDomains === false) {
      throw new SecurityError(
        ErrorCode.INVALID_ARGUMENT,
        'hsts.preload requires maxAge >= 31536000 (1y) and includeSubDomains=true',
      );
    }
    parts.push('preload');
  }
  return { name: 'Strict-Transport-Security', value: parts.join('; ') };
}

// Simple static-value policies

function staticHeader(name, defaultValue) {
  return options => {
    if (options === false) {
      return null;
    }
    if (options === true || options === undefined) {
      return { name, value: defaultValue };
    }
    if (isString(options)) {
      return { name, value: options };
    }
    if (isObject(options) && isString(options.value)) {
      return { name, value: options.value };
    }
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `${name} option must be true / false / a string / { value: string }`,
    );
  };
}

export const buildContentTypeOptions = staticHeader('X-Content-Type-Options', 'nosniff');
export const buildDnsPrefetchControl = staticHeader('X-DNS-Prefetch-Control', 'off');
export const buildDownloadOptions = staticHeader('X-Download-Options', 'noopen');
export const buildPermittedCrossDomain = staticHeader('X-Permitted-Cross-Domain-Policies', 'none');
export const buildOriginAgentCluster = staticHeader('Origin-Agent-Cluster', '?1');
// Legacy X-XSS-Protection is set to `0` to disable the buggy IE/Edge/Safari
// heuristics — modern browsers rely on CSP instead.
export const buildXssProtection = staticHeader('X-XSS-Protection', '0');
export const buildCoop = staticHeader('Cross-Origin-Opener-Policy', 'same-origin');
export const buildCoep = staticHeader('Cross-Origin-Embedder-Policy', 'require-corp');
export const buildCorp = staticHeader('Cross-Origin-Resource-Policy', 'same-origin');
export const buildReferrerPolicy = staticHeader('Referrer-Policy', 'no-referrer');

// X-Frame-Options
//
// Only DENY and SAMEORIGIN are supported by modern browsers. ALLOW-FROM was
// deprecated in favor of CSP's frame-ancestors directive — reject it here
// so users don't ship a header that browsers ignore.

const XFO_VALUES = new Set(['DENY', 'SAMEORIGIN']);

export function buildFrameguard(options) {
  if (options === false) {
    return null;
  }
  if (options === true || options === undefined) {
    return { name: 'X-Frame-Options', value: 'DENY' };
  }
  const action = isString(options) ? options : options?.action;
  if (!isString(action)) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      "frameguard option must be a string or { action: 'DENY' | 'SAMEORIGIN' }",
    );
  }
  const normalized = action.toUpperCase();
  if (!XFO_VALUES.has(normalized)) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `frameguard.action must be 'DENY' or 'SAMEORIGIN'; got '${action}'. Use CSP frame-ancestors for allow-lists.`,
    );
  }
  return { name: 'X-Frame-Options', value: normalized };
}

// Permissions-Policy
//
// Modern replacement for Feature-Policy. Serialized as
// `feature=(self "https://x.com"), feature2=()`. We accept a { feature:
// [origins] } object. An empty array disables the feature entirely.

export function buildPermissionsPolicy(options) {
  if (options === false || options === undefined) {
    return null;
  }
  if (options === true) {
    // Sensible-locked-down defaults: disable everything commonly abused.
    return {
      name: 'Permissions-Policy',
      value: [
        'accelerometer=()',
        'camera=()',
        'geolocation=()',
        'gyroscope=()',
        'magnetometer=()',
        'microphone=()',
        'payment=()',
        'usb=()',
      ].join(', '),
    };
  }
  const features = options.features ?? options;
  if (typeof features !== 'object' || features === null) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      'permissionsPolicy must be true / false / { feature: [origins] }',
    );
  }
  const parts = [];
  for (const [feature, allowlist] of Object.entries(features)) {
    if (!isArray(allowlist)) {
      throw new SecurityError(
        ErrorCode.INVALID_ARGUMENT,
        `permissionsPolicy feature '${feature}' allowlist must be an array; got ${typeof allowlist}`,
      );
    }
    const serialized = allowlist
      .map(origin => {
        if (origin === 'self' || origin === '*') {
          return origin;
        }
        // Origins are quoted, keywords like `self` are bare.
        return `"${origin}"`;
      })
      .join(' ');
    parts.push(`${kebab(feature)}=(${serialized})`);
  }
  return { name: 'Permissions-Policy', value: parts.join(', ') };
}
