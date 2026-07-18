// RFC 4648 Base32 codec — re-exported from the shared implementation.
// Case-insensitive on decode, no padding on encode (matches the Google
// Authenticator display convention). Callers wrap thrown plain errors
// into typed `OtpError`s at their surface boundary (see `secret.js`).
export { encode, decode } from '@exortek/shared/base32';
