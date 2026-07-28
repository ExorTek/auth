/**
 * WebAuthn / FIDO2 server verification.
 *
 * Two flows, two calls each:
 *
 * - Registration (add a passkey): `registration.begin()` → `registration.finish()`
 * - Authentication (sign in): `authentication.begin()` → `authentication.finish()`
 *
 * `begin` mints the JSON options the browser hands to
 * `navigator.credentials.{create,get}`; `finish` parses and verifies
 * the response the browser returns.
 *
 * Server-only.
 */

// Registration + authentication exports land here as each phase ships.
// Scaffold intentionally exports only the error surface for now.
export { PasskeyError, ErrorCode } from './errors.js';
