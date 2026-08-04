/**
 * Framework-agnostic core for the RP social-login middleware. Backends
 * serve every platform, so the flow supports two interaction modes over
 * the same `createOAuth` core (`authorize` → provider, `callback` →
 * user):
 *
 *   - **`web`** (server-rendered browser apps) — `GET` redirects; the flow
 *     session (`state` / PKCE `codeVerifier` / `nonce`) rides in an
 *     HMAC-signed httpOnly cookie, or in `createOAuth`'s server `store`.
 *   - **`api`** (mobile / SPA / CLI / desktop / TV) — JSON in, JSON out;
 *     the client holds the opaque flow session (like it already holds the
 *     PKCE verifier, RFC 8252 / AppAuth) and echoes it back on callback.
 *     No cookies, no redirects.
 *
 * The session travels three ways — cookie, server store, or client-held —
 * and `createOAuth` is agnostic to all three; this module only picks the
 * transport per mode. A `secret` makes the session tamper-evident (HMAC)
 * wherever the client can see it (cookie / client-held).
 */
import { createHash } from 'node:crypto';

import { encrypt as jweEncrypt, decrypt as jweDecrypt } from '@exortek/jwe';
import { hmac } from '@exortek/shared/hmac';
import { encode as base64urlEncode } from '@exortek/shared/base64url';
import { timingSafeEqual } from '@exortek/shared/timing-safe';
import { isFunction, isInteger, isNonEmptyString, isObject } from '@exortek/shared/predicates';

import { ErrorCode, OAuth2Error } from '../internal/errors.js';

// The flow session is sealed with `dir` + A256GCM under a key derived
// from the caller's secret — a full JWE (RFC 7516), symmetric.
const SEAL_ALG = 'dir';
const SEAL_ENC = 'A256GCM';

const DEFAULT_LOGIN_PATH = '/auth/:provider';
const DEFAULT_CALLBACK_PATH = '/auth/:provider/callback';
const DEFAULT_COOKIE_NAME = 'oauth_flow';
const DEFAULT_MAX_AGE_SEC = 600; // 10 minutes — matches the default maxAuthAge

/**
 * @typedef {'web' | 'api'} LoginMode
 *
 * @typedef {Object} LoginConfig
 * @property {ReturnType<import('../oauth.js').createOAuth>} oauth
 * @property {LoginMode} [mode='web']
 * @property {string} [loginPath='/auth/:provider']              start route (router `:provider` syntax)
 * @property {string} [callbackPath='/auth/:provider/callback']  MUST match the `callback` template given to createOAuth
 * @property {{ name?: string, secret?: string, path?: string, secure?: boolean, sameSite?: 'lax'|'strict'|'none', maxAge?: number }} [cookie]
 * @property {string} [secret]                         key to protect the client-held session (api mode)
 * @property {'sign' | 'jwe'} [seal='sign']            'sign' = HMAC (tamper-evident); 'jwe' = encrypt (also confidential)
 * @property {string[]} [scope]
 * @property {(ctx: object) => unknown} [onSuccess]
 * @property {(ctx: object) => unknown} [onError]
 * @property {string} [attach='oauth']
 */

/**
 * @param {LoginConfig} config
 */
export function normalizeLoginConfig(config) {
  if (!isObject(config) || !isObject(config.oauth) || !isFunction(config.oauth.authorize)) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'RP login middleware requires an { oauth } from createOAuth');
  }
  const mode = config.mode === 'api' ? 'api' : 'web';
  const cookie = isObject(config.cookie) ? config.cookie : {};
  // The protection key: `cookie.secret` in web mode, `secret` in api mode.
  const secret = mode === 'web' ? cookie.secret : (config.secret ?? cookie.secret);
  // `sign` (HMAC, tamper-evident) is the default; `jwe` additionally
  // encrypts so the client can't read state / verifier / nonce. Both need
  // a secret.
  const seal = config.seal === 'jwe' ? 'jwe' : 'sign';
  if (seal === 'jwe' && !isNonEmptyString(secret)) {
    throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, "seal: 'jwe' requires a secret");
  }

  return Object.freeze({
    oauth: config.oauth,
    mode,
    // The routes are taken verbatim, not built from a base — the callback
    // path must equal the `callback` template redirect_uri is derived from.
    loginPath: isNonEmptyString(config.loginPath) ? config.loginPath : DEFAULT_LOGIN_PATH,
    callbackPath: isNonEmptyString(config.callbackPath) ? config.callbackPath : DEFAULT_CALLBACK_PATH,
    // web mode uses a cookie only when a secret is present; otherwise the
    // server `store` on createOAuth carries the session.
    cookieMode: mode === 'web' && isNonEmptyString(secret),
    signed: isNonEmptyString(secret),
    seal,
    cookieName: isNonEmptyString(cookie.name) ? cookie.name : DEFAULT_COOKIE_NAME,
    secret,
    cookieOptions: {
      path: isNonEmptyString(cookie.path) ? cookie.path : '/',
      // `lax` lets the provider's top-level redirect carry the cookie back.
      sameSite: cookie.sameSite ?? 'lax',
      secure: cookie.secure ?? true,
      maxAge: isInteger(cookie.maxAge) ? cookie.maxAge : DEFAULT_MAX_AGE_SEC,
    },
    scope: config.scope,
    onSuccess: config.onSuccess,
    onError: config.onError,
    attach: isNonEmptyString(config.attach) ? config.attach : 'oauth',
  });
}

/**
 * Begin a login. Returns the provider `authorizeUrl`, the (optionally
 * signed) `session`, and — web + cookie mode — the cookie to set.
 *
 * @param {ReturnType<typeof normalizeLoginConfig>} config
 * @param {string} provider
 * @param {{ scope?: string[] }} [options]
 * @returns {Promise<{ authorizeUrl: string, session: string, warnings: unknown, setCookie: object | null }>}
 */
export async function startLogin(config, provider, options = {}) {
  const { url, session, warnings } = await config.oauth.authorize(provider, {
    scope: options.scope ?? config.scope,
  });
  const carried = await protectSession(config, session);

  return {
    authorizeUrl: url,
    session: carried,
    warnings,
    setCookie: config.cookieMode
      ? { name: config.cookieName, value: carried, options: { ...config.cookieOptions, httpOnly: true } }
      : null,
  };
}

/**
 * Complete a login. The session is recovered per mode: from the cookie
 * (web) or from the caller-supplied client-held value (api / store mode
 * passes neither and lets `createOAuth`'s store look it up by `state`).
 *
 * @param {ReturnType<typeof normalizeLoginConfig>} config
 * @param {string} provider
 * @param {Record<string, unknown>} query    the callback params (`code`, `state`, `iss`, …)
 * @param {{ cookieValue?: string, session?: string }} [carrier]
 * @returns {Promise<{ result: object, clearCookie: string | null }>}
 */
export async function completeLogin(config, provider, query, carrier = {}) {
  const raw = config.cookieMode ? carrier.cookieValue : carrier.session;
  let session;
  if (isNonEmptyString(raw)) {
    session = await unprotectSession(config, raw);
    if (!isNonEmptyString(session)) {
      throw new OAuth2Error(ErrorCode.MISSING_STATE, 'missing or tampered flow session');
    }
  } else if (config.mode === 'api' || config.cookieMode) {
    // These modes MUST carry a session; store mode legitimately has none.
    throw new OAuth2Error(ErrorCode.MISSING_STATE, 'no flow session supplied on the callback');
  }

  const result = await config.oauth.callback(provider, query, session ? { session } : {});
  return { result: { ...result, provider }, clearCookie: config.cookieMode ? config.cookieName : null };
}

// SESSION SIGNING (tamper-evidence wherever the client can see the value)

/**
 * `value.sig` with `sig = base64url(HMAC-SHA256(secret, value))`.
 *
 * @param {string} value @param {string} secret @returns {string}
 */
export function signValue(value, secret) {
  return `${value}.${base64urlEncode(hmac('sha256', secret, value))}`;
}

/**
 * Constant-time verify; returns the payload or `undefined` on any
 * signature mismatch.
 *
 * @param {string | undefined} signed @param {string} secret @returns {string | undefined}
 */
export function unsignValue(signed, secret) {
  if (!isNonEmptyString(signed)) {
    return undefined;
  }
  const dot = signed.lastIndexOf('.');
  if (dot === -1) {
    return undefined;
  }
  const value = signed.slice(0, dot);
  const a = Buffer.from(signed.slice(dot + 1));
  const b = Buffer.from(base64urlEncode(hmac('sha256', secret, value)));
  return a.length === b.length && timingSafeEqual(a, b) ? value : undefined;
}

/**
 * `seal: 'jwe'` — encrypt the session as a compact JWE (`dir` + A256GCM)
 * so the client sees only ciphertext, not the `state` / `codeVerifier` /
 * `nonce`. The key is derived from the caller's secret.
 *
 * @param {string} value @param {string} secret @returns {Promise<string>}
 */
export async function sealValue(value, secret) {
  return jweEncrypt(value, sealKey(secret), { alg: SEAL_ALG, enc: SEAL_ENC });
}

/**
 * Decrypt a sealed session; `undefined` on any failure (tampered / wrong
 * key / not a JWE).
 *
 * @param {string | undefined} sealed @param {string} secret @returns {Promise<string | undefined>}
 */
export async function unsealValue(sealed, secret) {
  if (!isNonEmptyString(sealed)) {
    return undefined;
  }
  try {
    const { payload } = await jweDecrypt(sealed, sealKey(secret), { alg: [SEAL_ALG], enc: [SEAL_ENC] });
    return Buffer.isBuffer(payload) ? payload.toString('utf8') : String(payload);
  } catch {
    return undefined;
  }
}

/** @param {string} secret @returns {Buffer} a 32-byte A256GCM key */
function sealKey(secret) {
  return createHash('sha256').update(secret).digest();
}

/**
 * Protect the flow session for transport per the configured strategy.
 *
 * @param {ReturnType<typeof normalizeLoginConfig>} config @param {string} value @returns {Promise<string>}
 */
async function protectSession(config, value) {
  if (config.seal === 'jwe') {
    return sealValue(value, config.secret);
  }
  return config.signed ? signValue(value, config.secret) : value;
}

/**
 * Recover a protected flow session; `undefined` when it fails to verify.
 *
 * @param {ReturnType<typeof normalizeLoginConfig>} config @param {string} raw @returns {Promise<string | undefined>}
 */
async function unprotectSession(config, raw) {
  if (config.seal === 'jwe') {
    return unsealValue(raw, config.secret);
  }
  return config.signed ? unsignValue(raw, config.secret) : raw;
}

/**
 * `web`-mode handoff: `onSuccess` if given, else attach to `req[attach]`
 * and continue (Express middleware chaining).
 *
 * @param {ReturnType<typeof normalizeLoginConfig>} config
 * @param {object} req @param {object} res @param {object} result @param {() => unknown} next
 */
export function handoff(config, req, res, result, next) {
  if (isFunction(config.onSuccess)) {
    return config.onSuccess({ req, res, ...result });
  }
  req[config.attach] = result;
  return next();
}
