import { createHmac } from 'node:crypto';

import { array, instanceOf, object, oneOf, optional, string, union } from '@exortek/shared/validate';

import { PasswordError, ErrorCode } from './errors.js';

const SecretItemSchema = union(string(), instanceOf(Uint8Array));

const PepperConfigSchema = object({
  secret: union(SecretItemSchema, array(SecretItemSchema)),
  hash: optional(oneOf(['sha256', 'sha512'])),
  encoding: optional(oneOf(['base64', 'hex'])),
});

/**
 * @typedef {object} PepperConfig
 * @property {string | Buffer | Uint8Array | Array<string | Buffer | Uint8Array>} secret
 *   The server-side pepper. Store this in a KMS, an env var, or a
 *   secrets manager — **never** in the same place as your password
 *   hashes. If the pepper ends up in the same dump as the hashes, it
 *   has bought you nothing.
 *
 *   Pass an array `[newest, …older]` to support **secret rotation** —
 *   new hashes use the first entry via `wrap`, and `verify` walks the
 *   list left-to-right so hashes minted under an older pepper still
 *   authenticate until you've rehashed them all. Cost is one HMAC per
 *   older secret you haven't cycled out yet.
 * @property {'sha256' | 'sha512'} [hash='sha256']
 *   HMAC digest. sha256 is fine and cheaper; sha512 if you're already
 *   on 512-bit rails elsewhere.
 * @property {string} [encoding='base64']
 *   'base64' → shorter, byte-safe for KDF input. 'hex' → prints nicely
 *   in logs but doubles length.
 */

/**
 * "Peppering" wraps a password with a server-side HMAC secret *before*
 * it enters the KDF. The user still enters their raw password; the DB
 * still stores an argon2/scrypt/bcrypt string. What changes: an attacker
 * who exfiltrates only the password-hash table cannot mount an offline
 * dictionary attack — they'd need the pepper too.
 *
 * Use with care:
 *
 *   - **Pepper is compile-time forever.** Rotating it invalidates every
 *     stored hash, so plan a rotation strategy (multi-pepper verify with
 *     newest-first fallback) if the value ever leaks.
 *   - **Store the pepper separately from the hashes.** In a KMS, an
 *     env var read from a secrets manager, or an HSM — not next to the
 *     `users` table.
 *   - **Not a replacement for a strong KDF.** Layer it, don't substitute.
 *
 * @example
 * const pepper = createPepper({ secret: process.env.PW_PEPPER })
 * const peppered = pepper.wrap(rawPassword)
 * const stored = await password.scrypt.hash(peppered)
 * // later
 * const ok = await password.scrypt.verify(pepper.wrap(candidate), stored)
 *
 * @param {PepperConfig} config
 */
export function createPepper(config) {
  try {
    PepperConfigSchema.parse(config, 'createPepper.config');
  } catch (err) {
    throw new PasswordError(ErrorCode.INVALID_ARGUMENT, err instanceof Error ? err.message : String(err));
  }
  const rawSecrets = Array.isArray(config.secret) ? config.secret : [config.secret];
  if (rawSecrets.length === 0) {
    throw new PasswordError(ErrorCode.INVALID_ARGUMENT, 'createPepper.config.secret: at least one secret is required');
  }
  const secrets = rawSecrets.map((s, i) => {
    const bytes = typeof s === 'string' ? Buffer.from(s, 'utf8') : Buffer.from(s);
    if (bytes.length < 16) {
      throw new PasswordError(
        ErrorCode.INVALID_ARGUMENT,
        `createPepper.config.secret[${i}]: must be at least 16 bytes for meaningful defence; got ${bytes.length}`,
      );
    }
    return bytes;
  });
  const hashName = config.hash ?? 'sha256';
  const encoding = config.encoding ?? 'base64';

  const wrapWith = (secretBytes, password) => {
    const pwBytes = typeof password === 'string' ? Buffer.from(password, 'utf8') : Buffer.from(password);
    return createHmac(hashName, secretBytes).update(pwBytes).digest(encoding);
  };

  return {
    /**
     * Wrap a password with the **current** (newest) pepper. The result is
     * a fixed-length digest string safe to feed straight into
     * `hash()` / `verify()`. New hashes should always be minted with this
     * — old ones stay verifiable via {@link wrapAll}.
     * @param {string | Buffer | Uint8Array} password
     * @returns {string}
     */
    wrap(password) {
      if (typeof password !== 'string' && !Buffer.isBuffer(password) && !(password instanceof Uint8Array)) {
        throw new PasswordError(ErrorCode.INVALID_ARGUMENT, 'pepper.wrap: password is required');
      }
      return wrapWith(secrets[0], password);
    },

    /**
     * Wrap a password with **every configured pepper**, newest first.
     * Returns an array the caller walks through `verify` — the first
     * that authenticates wins. This is the rotation hot path:
     *
     *   const candidates = pepper.wrapAll(input)
     *   for (const peppered of candidates) {
     *     if (await password.verify(peppered, storedHash)) {
     *       if (candidates.indexOf(peppered) > 0) {
     *         // matched under an older pepper — rehash under the current one
     *         const fresh = await password.scrypt.hash(candidates[0])
     *         await db.users.update(userId, { pw_hash: fresh })
     *       }
     *       return true
     *     }
     *   }
     *   return false
     *
     * With a single secret configured this returns a one-element array
     * and behaves identically to `wrap`.
     *
     * @param {string | Buffer | Uint8Array} password
     * @returns {string[]}
     */
    wrapAll(password) {
      if (typeof password !== 'string' && !Buffer.isBuffer(password) && !(password instanceof Uint8Array)) {
        throw new PasswordError(ErrorCode.INVALID_ARGUMENT, 'pepper.wrapAll: password is required');
      }
      return secrets.map(s => wrapWith(s, password));
    },

    /**
     * How many peppers are configured. Handy for a health-check log
     * ("rotating from N=2 down to N=1 once migration completes").
     */
    get size() {
      return secrets.length;
    },
  };
}
