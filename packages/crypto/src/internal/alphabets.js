/**
 * Character alphabets shared across the `random` module.
 *
 * Kept in one place so that (a) rejection-sampling helpers don't repeat
 * the same 62-char literal in every caller, and (b) any future addition
 * (e.g. a URL-safe subset that omits look-alike characters) plugs in
 * without touching each generator.
 */

export const DIGITS = '0123456789';
export const LOWER = 'abcdefghijklmnopqrstuvwxyz';
export const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

/** All 62 alphanumeric characters — nanoid-style ID alphabet. */
export const ALPHANUM = UPPER + LOWER + DIGITS;

/** Uppercase alphanumeric — invoice / tracking / license ID convention. */
export const UPPER_ALPHANUM = UPPER + DIGITS;

/**
 * Crockford base32 alphabet (ULID). 32 chars, deliberately omits `I`,
 * `L`, `O`, `U` for visual clarity and to avoid accidental profanity.
 */
export const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/**
 * Bitcoin base58 alphabet. Omits `0`, `O`, `I`, `l` to avoid
 * look-alike confusion. Common in crypto-wallet address formats and
 * short human-readable identifiers.
 */
export const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
