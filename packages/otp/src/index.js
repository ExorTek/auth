export { generateSecret, decodeSecret } from './secret.js';
export { hotp, verifyHotp, resynchronize } from './hotp.js';
export { totp, verifyTotp, remainingSeconds } from './totp.js';
export { provisioningUri, parseProvisioningUri } from './uri.js';
export { backupCodes, normalizeBackupCode, compareBackupCode, verifyBackupCode, backupPresets } from './backup.js';
export { enroll } from './enroll.js';
export { OtpError, ErrorCode } from './internal/errors.js';

/**
 * @typedef {import('./hotp.js').OtpAlgorithm} OtpAlgorithm
 * @typedef {import('./hotp.js').HotpOptions} HotpOptions
 * @typedef {import('./hotp.js').HotpVerifyOptions} HotpVerifyOptions
 * @typedef {import('./totp.js').TotpOptions} TotpOptions
 * @typedef {import('./totp.js').TotpVerifyOptions} TotpVerifyOptions
 * @typedef {import('./totp.js').ReplayGuard} ReplayGuard
 * @typedef {import('./uri.js').ProvisioningOptions} ProvisioningOptions
 * @typedef {import('./uri.js').ProvisioningType} ProvisioningType
 * @typedef {import('./secret.js').SecretOptions} SecretOptions
 * @typedef {import('./secret.js').SecretEncoding} SecretEncoding
 * @typedef {import('./backup.js').BackupCodesOptions} BackupCodesOptions
 */
