/**
 * Offline AAGUID → authenticator-name lookup.
 *
 * Public API for the `@exortek/passkey/aaguid` subpath. Ships a
 * hand-curated baseline; refresh via `scripts/refresh-aaguid-
 * table.mjs` when a new FIDO MDS3 blob is available.
 *
 * Usage:
 *   import { lookup } from '@exortek/passkey/aaguid';
 *   lookup('ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4');
 *   // → { name: 'Google Password Manager' }
 *   lookup('unknown-uuid');
 *   // → null
 */

export { AAGUID_TABLE as table, lookup } from '../data/aaguid-table.js';
