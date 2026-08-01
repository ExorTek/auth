/**
 * The PASETO version/purpose registry. A token's leading `vN.purpose.`
 * bytes bind the exact primitive set — this is what makes PASETO immune
 * to the algorithm-confusion attacks that plague JWT: there is no
 * negotiable `alg` header, the version dictates the primitive.
 *
 * The scaffold registers the curated set; the discussion below decides
 * whether v3 legacy ships at all. See README "Version policy".
 *
 *   v4.local    XChaCha20 + keyed BLAKE2b (enc-then-MAC)  — recommended, internal
 *   v4.public   Ed25519                                   — recommended, external
 *   v3.local    AES-256-CTR + HMAC-SHA384 (enc-then-MAC)  — legacy / FIPS interop
 *   v3.public   ECDSA P-384 (raw r‖s over SHA-384)        — legacy / FIPS interop
 */

export const V4_LOCAL = 'v4.local';
export const V4_PUBLIC = 'v4.public';
export const V3_LOCAL = 'v3.local';
export const V3_PUBLIC = 'v3.public';

/** Curated, modern default. `verify`/`decrypt` accept these unless overridden. */
export const SUPPORTED = Object.freeze([V4_LOCAL, V4_PUBLIC]);
