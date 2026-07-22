/**
 * Token codec for `@exortek/apikey`.
 *
 * **Wire format:**
 *
 *     <prefix>_<base64url(16 random bytes)>_<base64url(32 random bytes)>
 *     ^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^
 *     type     id (128-bit — plaintext DB key)   secret (256-bit — HMAC'd)
 *
 *   sk_live_QVI0RExDX01Fbg_pTk9UX0FfUkVBTF9LRVlfNDJfQVJUSVNBTkFMX1BJWk
 *
 * Stripe / GitHub / Anthropic all use this three-segment shape. The
 * split matters:
 *
 * - The **id** is stored in the clear so a request's incoming key can
 *   be found in the DB with a single O(1) primary-key lookup. It is not
 *   secret: an attacker who guesses an id alone cannot verify — the
 *   secret half is still gated by the HMAC compare.
 * - The **secret** is never stored in the clear. Storage keeps only
 *   `HMAC-SHA256(secret, pepper)` (or plain SHA-256 when no pepper is
 *   configured). API keys are random 256-bit values — a fast hash is
 *   fine for storage; slow KDFs like Argon2 exist for low-entropy
 *   passwords, not for cryptographically random secrets.
 * - The **pepper** (optional) is a server-side secret held in the app
 *   env, not the DB. A stolen database on its own does not let an
 *   attacker offline-brute the stored hashes; they also need the
 *   pepper. Peppers rotate via a newest-first array.
 *
 * The whole key is opaque to holders — do not parse the segments in
 * client code; only the server's `parseApiKey` sees them.
 */

import { createHmac, createHash, randomBytes, timingSafeEqual as nodeTimingSafeEqual } from 'node:crypto';
import * as b64u from '@exortek/shared/base64url';
import * as crockford from '@exortek/shared/crockford';
import { isBytes, isString } from '@exortek/shared/predicates';
import { timingSafeEqual } from '@exortek/shared/timing-safe';

const ID_BYTES = 16;
const SECRET_BYTES = 32;

// Base32-Crockford alphabet is [0-9A-HJKMNP-TV-Z] — no ambiguous
// glyphs (`I`, `L`, `O`, `U` excluded), no separators (`_` reserved as
// our own delimiter), URL-safe, human-transcribable. 16 bytes → 26
// chars for the id; 32 bytes → 52 chars for the secret. The wire key
// is unambiguously three underscore-separated segments.
const ID_CHARS = 26;
const SECRET_CHARS = 52;
const CROCKFORD_RE = /^[0-9A-HJKMNP-TV-Z]+$/;

/**
 * Prefix grammar — Stripe-style: lowercase alpha, digits, underscore
 * separators between 1-4 lower-alphanumeric segments. Keeps the token
 * unambiguously parseable and safe to embed in URLs / headers.
 *
 *   sk_live      ✓
 *   pk_test      ✓
 *   svc_prod_v2  ✓
 *   sk__live     ✗ (empty segment)
 *   sk_live_     ✗ (trailing underscore)
 *   Sk_Live      ✗ (uppercase)
 */
const PREFIX_RE = /^[a-z][a-z0-9]{0,15}(_[a-z0-9]{1,15}){0,3}$/;

/**
 * @param {string} prefix
 * @param {string} name
 * @param {(msg: string) => Error} invalidArg
 * @returns {string}
 */
export function assertPrefix(prefix, name, invalidArg) {
  if (!isString(prefix) || !PREFIX_RE.test(prefix)) {
    throw invalidArg(
      `${name} must match /^[a-z][a-z0-9]{0,15}(_[a-z0-9]{1,15}){0,3}$/ — Stripe-style lowercase with underscore-separated segments (e.g. 'sk_live', 'pk_test'); got ${JSON.stringify(prefix)}`,
    );
  }
  return prefix;
}

/**
 * Mint the raw pieces of a new key. Returns the wire token, the
 * plaintext id (for DB lookup), and the storage hash of the secret.
 *
 * @param {string} prefix
 * @param {Buffer | null} pepper   Newest pepper, or null when unconfigured.
 * @returns {{ key: string, id: string, hash: string }}
 */
export function mint(prefix, pepper) {
  const id = crockford.encode(randomBytes(ID_BYTES));
  const secretBytes = randomBytes(SECRET_BYTES);
  const secret = crockford.encode(secretBytes);
  const key = `${prefix}_${id}_${secret}`;
  const hash = hashSecret(secretBytes, pepper);
  return { key, id, hash };
}

/**
 * Compute the storage hash of a raw secret. With a pepper: HMAC-SHA256
 * keyed by the pepper. Without: plain SHA-256. Both return the digest
 * as a 43-char base64url string.
 *
 * @param {Buffer} secretBytes
 * @param {Buffer | null} pepper
 * @returns {string}
 */
export function hashSecret(secretBytes, pepper) {
  const digest = pepper
    ? createHmac('sha256', pepper).update(secretBytes).digest()
    : createHash('sha256').update(secretBytes).digest();
  return b64u.encode(digest);
}

/**
 * Timing-safe compare of a candidate hash against a stored hash. Both
 * inputs are base64url strings of equal length — a length mismatch is
 * treated as a mismatch after a fixed decode step, so an outside
 * observer cannot learn the stored hash's length via timing.
 *
 * @param {string} candidate
 * @param {string} stored
 * @returns {boolean}
 */
export function hashesMatch(candidate, stored) {
  if (!isString(candidate) || !isString(stored) || candidate.length !== stored.length) {
    return false;
  }
  let a;
  let b;
  try {
    a = b64u.decode(candidate);
    b = b64u.decode(stored);
  } catch {
    return false;
  }
  return timingSafeEqual(a, b);
}

/**
 * Parse a raw key without verifying it. Returns the segments, or
 * `null` when the shape is wrong. Never throws.
 *
 * Callers can use `parseApiKey(key).prefix` to route by key family
 * in a middleware before hitting the store — but the parse result
 * MUST NOT be trusted as authenticated. Only `verifyApiKey` proves
 * the holder possesses the real secret.
 *
 * @param {string} key
 * @returns {{ prefix: string, id: string, secret: string } | null}
 */
export function parseApiKey(key) {
  if (!isString(key)) {
    return null;
  }
  // The prefix may contain '_' (`sk_live`, `svc_prod_v2`), but id and
  // secret use the base32-crockford alphabet which contains no
  // underscores — so the last two '_' cleanly bound them.
  const lastUnderscore = key.lastIndexOf('_');
  if (lastUnderscore <= 0) {return null;}
  const prevUnderscore = key.lastIndexOf('_', lastUnderscore - 1);
  if (prevUnderscore <= 0) {return null;}
  const prefix = key.slice(0, prevUnderscore);
  const id = key.slice(prevUnderscore + 1, lastUnderscore);
  const secret = key.slice(lastUnderscore + 1);
  if (!PREFIX_RE.test(prefix)) {return null;}
  if (id.length !== ID_CHARS || !CROCKFORD_RE.test(id)) {return null;}
  if (secret.length !== SECRET_CHARS || !CROCKFORD_RE.test(secret)) {return null;}
  return { prefix, id, secret };
}

/**
 * Compute the storage hash for a candidate raw key's secret half,
 * trying peppers newest-first. Returns the hash + which pepper matched
 * (or null if no pepper array was supplied).
 *
 * Used by `verifyApiKey` — it hashes the incoming secret with each
 * pepper in the rotation and lets the caller decide which one to
 * compare against. The needsRehash signal (secret matched an older
 * pepper) is exposed to consumers so they can silently upgrade
 * storage on the next successful auth.
 *
 * @param {string} rawSecret     The base64url secret segment.
 * @param {Buffer[] | null} peppers
 * @returns {{ candidateHashes: string[] }}
 */
export function candidateHashesFor(rawSecret, peppers) {
  let secretBytes;
  try {
    secretBytes = crockford.decode(rawSecret);
  } catch {
    return { candidateHashes: [] };
  }
  if (!peppers || peppers.length === 0) {
    return { candidateHashes: [hashSecret(secretBytes, null)] };
  }
  return {
    candidateHashes: peppers.map(p => hashSecret(secretBytes, p)),
  };
}

/**
 * Log-safe display for a key. Returns `<prefix>_<first-N-of-id>…<last-M-of-secret>`
 * so the value is recognisable in an audit log without disclosing the
 * secret. The default masks all but the first 6 chars of the id and
 * the last 4 chars of the secret.
 *
 * @param {string} key
 * @returns {string}
 */
export function mask(key) {
  const parsed = parseApiKey(key);
  if (!parsed) {
    return typeof key === 'string' ? key.slice(0, 3) + '…' : '<invalid>';
  }
  const idHint = parsed.id.slice(0, 6);
  const secretTail = parsed.secret.slice(-4);
  return `${parsed.prefix}_${idHint}…${secretTail}`;
}

// Re-export node's raw timing-safe for tests that want to sanity-check
// against the primitive directly — not part of the public surface.
export { nodeTimingSafeEqual as _nodeTimingSafeEqual, isBytes as _isBytes };
