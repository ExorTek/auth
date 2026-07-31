/**
 * Per-key async mutex — re-exported from the shared implementation.
 * Serialises concurrent `rotate` calls for the same refresh token in the
 * in-process store; Redis relies on its atomic Lua CAS instead.
 */
export { createKeyMutex } from '@exortek/shared/mutex';
