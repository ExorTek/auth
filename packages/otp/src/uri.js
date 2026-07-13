import { OtpError, ErrorCode } from './internal/errors.js';

// Google's Key URI Format (the de facto QR standard used by every
// mainstream 2FA app) only lists SHA1 / SHA256 / SHA512. SHA224 and
// SHA384 work at the HMAC layer but no Authenticator app will parse
// them from a QR — refuse them here so a caller can't accidentally
// mint an unusable enrollment code.
const URI_SUPPORTED_ALGORITHMS = new Set(['SHA1', 'SHA256', 'SHA512']);

/**
 * @typedef {'totp' | 'hotp'} ProvisioningType
 */

/**
 * @typedef {object} ProvisioningOptions
 * @property {string} label
 *   Account identifier — typically the user's email or username.
 *   Rendered in the Authenticator app's list.
 * @property {string} secret
 *   Base32-encoded secret. Do NOT pass the raw Buffer.
 * @property {string} [issuer]
 *   Your app name. Shows above the account label in the app UI and
 *   is duplicated into the label per the Google Authenticator
 *   Key URI Format recommendation.
 * @property {ProvisioningType} [type='totp']
 * @property {6 | 7 | 8 | 9 | 10} [digits=6]
 * @property {number} [period=30]                   TOTP only.
 * @property {number} [counter]                     HOTP only — required for hotp type.
 * @property {'SHA1' | 'SHA256' | 'SHA512'} [algorithm='SHA1']
 */

/**
 * Build an `otpauth://` provisioning URI — the string you render as a
 * QR code on the enrollment screen. Compatible with Google
 * Authenticator, Authy, 1Password, Bitwarden, Yubico Authenticator,
 * Aegis, and every other mainstream 2FA app.
 *
 * The format is documented at:
 *   https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 *
 * @param {ProvisioningOptions} options
 * @returns {string}
 */
export function provisioningUri(options) {
  if (!options || typeof options !== 'object') {
    throw new OtpError(ErrorCode.INVALID_ARGUMENT, 'provisioningUri: options required');
  }
  const type = options.type ?? 'totp';
  if (type !== 'totp' && type !== 'hotp') {
    throw new OtpError(ErrorCode.INVALID_ARGUMENT, `provisioningUri: type must be 'totp' or 'hotp'; got '${type}'`);
  }
  if (typeof options.label !== 'string' || options.label.length === 0) {
    throw new OtpError(ErrorCode.INVALID_ARGUMENT, 'provisioningUri: label required');
  }
  if (typeof options.secret !== 'string' || options.secret.length === 0) {
    throw new OtpError(ErrorCode.INVALID_ARGUMENT, 'provisioningUri: secret required (base32 string)');
  }
  if (type === 'hotp' && !Number.isInteger(options.counter)) {
    throw new OtpError(ErrorCode.INVALID_ARGUMENT, 'provisioningUri: counter required (integer) for hotp type');
  }
  if (options.algorithm && !URI_SUPPORTED_ALGORITHMS.has(options.algorithm)) {
    throw new OtpError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      `provisioningUri: algorithm '${options.algorithm}' is not in Google's Key URI Format spec (SHA1 / SHA256 / SHA512). No Authenticator app will parse a QR with this value. Use SHA1 for maximum compatibility; SHA256 and SHA512 work in Authy / 1Password / Bitwarden / Aegis but NOT stock Google Authenticator pre-2023 (SHA512 still unsupported).`,
    );
  }

  // Per Google's Key URI Format, when both an `issuer=` parameter and
  // an "Issuer:Account" label are present, apps SHOULD prefer the
  // parameter — but historic apps rely on the label prefix. So we
  // always emit both when an issuer is given.
  const label = options.issuer
    ? `${encodeURIComponent(options.issuer)}:${encodeURIComponent(options.label)}`
    : encodeURIComponent(options.label);

  const params = new URLSearchParams();
  // Strip padding for max compatibility — some scanners choke on `=`.
  params.set('secret', options.secret.replace(/=+$/, ''));
  if (options.issuer) {
    params.set('issuer', options.issuer);
  }
  if (options.algorithm && options.algorithm !== 'SHA1') {
    params.set('algorithm', options.algorithm);
  }
  if (options.digits && options.digits !== 6) {
    params.set('digits', String(options.digits));
  }
  if (type === 'totp' && options.period && options.period !== 30) {
    params.set('period', String(options.period));
  }
  if (type === 'hotp') {
    params.set('counter', String(options.counter));
  }

  return `otpauth://${type}/${label}?${params.toString()}`;
}

/**
 * @typedef {object} ParsedProvisioning
 * @property {'totp' | 'hotp'} type
 * @property {string} label            The account identifier — the
 *                                     "Issuer:" prefix (if any) is stripped.
 * @property {string} secret           Base32, unpadded — pass straight into `totp` / `hotp`.
 * @property {string | undefined} issuer
 * @property {6 | 7 | 8 | undefined} digits
 * @property {number | undefined} period    TOTP only.
 * @property {number | undefined} counter   HOTP only.
 * @property {'SHA1' | 'SHA224' | 'SHA256' | 'SHA384' | 'SHA512' | undefined} algorithm
 */

/**
 * Parse an `otpauth://` provisioning URI back into its parts — the
 * inverse of {@link provisioningUri}. Handy for migration flows where
 * you decode a QR the user scanned from another app.
 *
 * Returns `null` for anything that isn't a well-formed provisioning
 * URI. Never throws on malformed input.
 *
 *   const info = parseProvisioningUri(qrPayload)
 *   if (!info) return res.status(400).end('invalid QR')
 *   await db.users.upsert(userId, { secret: info.secret })
 *
 * @param {unknown} input
 * @returns {ParsedProvisioning | null}
 */
export function parseProvisioningUri(input) {
  if (typeof input !== 'string' || input.length === 0) {
    return null;
  }
  let url;
  try {
    url = new URL(input);
  } catch {
    return null;
  }
  if (url.protocol !== 'otpauth:') {
    return null;
  }
  // WHATWG URL parses `otpauth://totp/Issuer:user` with `totp` as the
  // host and `/Issuer:user` as the pathname.
  const type = url.hostname.toLowerCase();
  if (type !== 'totp' && type !== 'hotp') {
    return null;
  }

  // Pathname always starts with '/'. The label may itself be URL-encoded.
  const rawPath = url.pathname.slice(1);
  if (!rawPath) {
    return null;
  }
  let labelSegment;
  try {
    labelSegment = decodeURIComponent(rawPath);
  } catch {
    return null;
  }
  // Split off an "Issuer:" prefix, if present.
  const colon = labelSegment.indexOf(':');
  const labelIssuer = colon > 0 ? labelSegment.slice(0, colon).trim() : undefined;
  const label = colon > 0 ? labelSegment.slice(colon + 1).trim() : labelSegment.trim();
  if (!label) {
    return null;
  }

  const params = url.searchParams;
  const secret = (params.get('secret') ?? '').replace(/\s+/g, '');
  if (!secret) {
    return null;
  }
  const issuerParam = params.get('issuer') ?? undefined;
  // Prefer the query-parameter issuer per the Key URI Format spec —
  // fall back to the label prefix. Both are lenient inputs, so we trust
  // whichever showed up.
  const issuer = issuerParam || labelIssuer;

  const algorithmRaw = params.get('algorithm');
  const algorithm = algorithmRaw ? algorithmRaw.toUpperCase() : undefined;

  const digitsRaw = params.get('digits');
  const digits = digitsRaw ? Number.parseInt(digitsRaw, 10) : undefined;

  const periodRaw = params.get('period');
  const period = periodRaw ? Number.parseInt(periodRaw, 10) : undefined;

  const counterRaw = params.get('counter');
  const counter = counterRaw ? Number.parseInt(counterRaw, 10) : undefined;

  // HOTP MUST carry a counter; without one the QR is unusable.
  if (type === 'hotp' && (counter === undefined || Number.isNaN(counter))) {
    return null;
  }

  return {
    type,
    label,
    secret,
    issuer,
    algorithm: algorithm && algorithm !== '' ? algorithm : undefined,
    digits: Number.isFinite(digits) && digits > 0 ? digits : undefined,
    period: Number.isFinite(period) && period > 0 ? period : undefined,
    counter: Number.isFinite(counter) ? counter : undefined,
  };
}
