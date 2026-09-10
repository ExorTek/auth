/**
 * `@exortek/oidc` — OpenID Connect Core 1.0 for Node.js.
 *
 * The root entry re-exports the two halves and the shared error surface.
 * Import the relying-party client from `@exortek/oidc/client` and the
 * OpenID Provider from `@exortek/oidc/provider` when you want only one
 * side bundled; this barrel is the convenience re-export.
 */
export { createClient } from './client/index.js';
export { createProvider } from './provider/index.js';
export { ErrorCode, OidcError } from './internal/errors.js';
