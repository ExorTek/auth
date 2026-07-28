/**
 * WebAuthn / FIDO2 server verification.
 *
 * Two flows, two calls each:
 *   - Registration: `registration.begin` → `registration.finish`
 *   - Authentication: `authentication.begin` → `authentication.finish`
 *
 * Server-only.
 */

export * as registration from './registration/index.js';
export * as authentication from './authentication/index.js';
export { PasskeyError, ErrorCode } from './errors.js';
