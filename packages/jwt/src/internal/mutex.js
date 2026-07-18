/**
 * Per-key async mutex — re-exported from the shared implementation.
 * Only useful for the in-process store; Redis / other multi-process
 * stores need their own atomic primitive.
 */
export { createKeyMutex } from '@exortek/shared/mutex';
