import { generateSecret } from './secret.js';
import { provisioningUri } from './uri.js';
import { backupCodes } from './backup.js';
import { OtpError, ErrorCode } from './internal/errors.js';

/**
 * @typedef {object} EnrollOptions
 * @property {string} label
 *   Account identifier — usually the user's email or username.
 *   Rendered in the Authenticator app.
 * @property {string} [issuer]
 *   Your app name. Shows above the account label in the app UI.
 * @property {'totp' | 'hotp'} [type='totp']
 * @property {6 | 7 | 8 | 9 | 10} [digits=6]
 * @property {number} [period=30]                 TOTP only.
 * @property {number} [counter=0]                 HOTP only — starting counter.
 * @property {import('./hotp.js').OtpAlgorithm} [algorithm='SHA1']
 * @property {import('./secret.js').SecretOptions} [secretOptions]
 *   Overrides for the underlying `generateSecret` call — bytes, encoding.
 * @property {number} [backupCodeCount=10]
 *   Set to `0` to skip generating backup codes.
 * @property {import('./backup.js').BackupCodesOptions} [backupCodeOptions]
 *   Passed straight to `backupCodes` — shape, alphabet, groups.
 */

/**
 * @typedef {object} EnrollmentBundle
 * @property {string} secret            Base32-encoded secret to save.
 * @property {string} uri               `otpauth://` URI — render as QR.
 * @property {string[]} backupCodes     One-time recovery codes. Empty
 *                                      array when `backupCodeCount: 0`.
 */

/**
 * One-call enrollment — mint a secret, build the provisioning URI, and
 * generate backup codes in a single step.
 *
 *   const { secret, uri, backupCodes } = enroll({
 *     label: 'alice@example.com',
 *     issuer: 'MyApp',
 *   })
 *   // Save `secret` and hashed(backupCodes) server-side.
 *   // Render `uri` as a QR on the enrollment page.
 *
 * The bundle is composed from `generateSecret` + `provisioningUri` +
 * `backupCodes` — everything each helper accepts is passed through so
 * you can still tune individual pieces (algorithm, period, backup code
 * format, etc.) without dropping down to primitives.
 *
 * @param {EnrollOptions} options
 * @returns {EnrollmentBundle}
 */
export function enroll(options) {
  if (!options || typeof options !== 'object') {
    throw new OtpError(ErrorCode.INVALID_ARGUMENT, 'enroll: options required');
  }
  if (typeof options.label !== 'string' || options.label.length === 0) {
    throw new OtpError(ErrorCode.INVALID_ARGUMENT, 'enroll: label required');
  }
  const type = options.type ?? 'totp';
  const backupCodeCount = options.backupCodeCount ?? 10;

  const secret = generateSecret(options.secretOptions);
  const uri = provisioningUri({
    label: options.label,
    secret,
    issuer: options.issuer,
    type,
    digits: options.digits,
    period: options.period,
    counter: type === 'hotp' ? (options.counter ?? 0) : undefined,
    algorithm: options.algorithm,
  });
  const codes = backupCodeCount > 0 ? backupCodes(backupCodeCount, options.backupCodeOptions) : [];

  return { secret, uri, backupCodes: codes };
}
