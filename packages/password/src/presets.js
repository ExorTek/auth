import { scryptDefaults } from './algorithms/scrypt.js';
import { pbkdf2Defaults, pbkdf2OwaspIterations } from './algorithms/pbkdf2.js';
import { argon2Defaults } from './algorithms/argon2.js';
import { bcryptDefaults } from './algorithms/bcrypt.js';

/**
 * Ready-made parameter bundles for common threat models. Feed them
 * directly into the algorithm's `hash` call:
 *
 *   await password.argon2.hash(pw, presets.owasp2024.argon2)
 *   await password.scrypt.hash(pw, presets.owasp2024.scrypt)
 *
 * The `owasp2024` bundle is what the individual algorithm modules use as
 * their **built-in defaults** — passing it explicitly is redundant but
 * documents intent. `fips` sticks to PBKDF2-SHA-256 for environments
 * where FIPS 140-3 compliance is a hard requirement; `sensitive` cranks
 * the memory/time knobs for KMS-style long-lived credentials.
 */
export const presets = Object.freeze({
  /**
   * OWASP Password Storage Cheat Sheet — 2024 first-line recommendations.
   * Balances user-visible latency (~200ms) against hardware-attack cost.
   */
  owasp2024: Object.freeze({
    argon2: Object.freeze({ ...argon2Defaults }),
    scrypt: Object.freeze({ ...scryptDefaults }),
    bcrypt: Object.freeze({ ...bcryptDefaults }),
    pbkdf2: Object.freeze({ ...pbkdf2Defaults, iterations: pbkdf2OwaspIterations.sha256 }),
  }),

  /**
   * FIPS 140-3 / NIST SP 800-132 compliant. Only PBKDF2 is a NIST-approved
   * KDF; scrypt and argon2 are not (regardless of their real-world
   * strength). Use these settings only when the compliance auditor
   * demands it.
   */
  fips: Object.freeze({
    pbkdf2: Object.freeze({
      hash: 'sha256',
      iterations: pbkdf2OwaspIterations.sha256,
      keyLength: 32,
      saltLength: 16,
    }),
  }),

  /**
   * Sensitive-credential mode. Multiplies memory and time cost roughly 4x
   * the OWASP baseline — verify takes ~1s per attempt, which is fine for
   * a KMS unwrap or an admin login screen but too slow for a
   * high-throughput consumer signup flow.
   */
  sensitive: Object.freeze({
    argon2: Object.freeze({
      type: 'argon2id',
      memoryCost: 64 * 1024,
      timeCost: 4,
      parallelism: 1,
      hashLength: 32,
      saltLength: 16,
    }),
    scrypt: Object.freeze({
      N: 1 << 19,
      r: 8,
      p: 1,
      keyLength: 32,
      saltLength: 16,
    }),
    bcrypt: Object.freeze({ rounds: 14, mode: 'prehash' }),
    pbkdf2: Object.freeze({
      hash: 'sha512',
      iterations: 1_000_000,
      keyLength: 64,
      saltLength: 16,
    }),
  }),

  /**
   * Interactive-latency mode. Halves the OWASP defaults for verify
   * targets around 50-80ms — appropriate for high-throughput login
   * endpoints where you're accepting a small hardness-cost reduction
   * for a big UX win.
   */
  interactive: Object.freeze({
    argon2: Object.freeze({
      type: 'argon2id',
      memoryCost: 12 * 1024,
      timeCost: 2,
      parallelism: 1,
      hashLength: 32,
      saltLength: 16,
    }),
    scrypt: Object.freeze({
      N: 1 << 15,
      r: 8,
      p: 1,
      keyLength: 32,
      saltLength: 16,
    }),
    bcrypt: Object.freeze({ rounds: 10, mode: 'prehash' }),
  }),
});
