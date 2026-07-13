import * as scrypt from './algorithms/scrypt.js';
import * as pbkdf2 from './algorithms/pbkdf2.js';
import * as argon2 from './algorithms/argon2.js';
import * as bcrypt from './algorithms/bcrypt.js';
import { verify, needsRehash, identifyAlgorithm, constantTimeVerify } from './verify.js';
import { strength } from './strength.js';
import { generate, passphrase, alphabets } from './generate.js';
import { policy, assertPolicy } from './policy.js';
import { createPepper } from './pepper.js';
import { createHistory } from './history.js';
import { presets } from './presets.js';
import { parseHash, serialiseHash } from './phc.js';
import { PasswordError, ErrorCode } from './errors.js';

/**
 * Umbrella facade — all four algorithms under their own namespace, plus
 * the cross-algorithm `verify` / `needsRehash` routers and every helper.
 *
 * Tree-shakers see through this — importing only `password.scrypt` from a
 * bundler pulls scrypt and its dependencies, nothing else. If you're
 * building for a strict bundle-size budget, prefer the subpath imports:
 *
 *   import { scrypt } from '@exortek/password/scrypt'
 *   import { argon2 } from '@exortek/password/argon2'
 */
export const password = Object.freeze({
  scrypt,
  pbkdf2,
  argon2,
  bcrypt,
  verify,
  constantTimeVerify,
  needsRehash,
  identifyAlgorithm,
  strength,
  generate,
  passphrase,
  alphabets,
  policy,
  assertPolicy,
  createPepper,
  createHistory,
  presets,
  parseHash,
  serialiseHash,
});

export {
  scrypt,
  pbkdf2,
  argon2,
  bcrypt,
  verify,
  constantTimeVerify,
  needsRehash,
  identifyAlgorithm,
  strength,
  generate,
  passphrase,
  alphabets,
  policy,
  assertPolicy,
  createPepper,
  createHistory,
  presets,
  parseHash,
  serialiseHash,
  PasswordError,
  ErrorCode,
};

/**
 * @typedef {import('./phc.js').PasswordAlgorithm} PasswordAlgorithm
 * @typedef {import('./phc.js').ParsedHash} ParsedHash
 * @typedef {import('./algorithms/scrypt.js').ScryptHashOptions} ScryptHashOptions
 * @typedef {import('./algorithms/pbkdf2.js').Pbkdf2HashOptions} Pbkdf2HashOptions
 * @typedef {import('./algorithms/argon2.js').Argon2HashOptions} Argon2HashOptions
 * @typedef {import('./algorithms/argon2.js').Argon2Type} Argon2Type
 * @typedef {import('./algorithms/bcrypt.js').BcryptHashOptions} BcryptHashOptions
 * @typedef {import('./algorithms/bcrypt.js').BcryptMode} BcryptMode
 * @typedef {import('./verify.js').VerifyOptions} VerifyOptions
 * @typedef {import('./verify.js').NeedsRehashOptions} NeedsRehashOptions
 * @typedef {import('./strength.js').StrengthResult} StrengthResult
 * @typedef {import('./strength.js').StrengthOptions} StrengthOptions
 * @typedef {import('./strength.js').Weakness} Weakness
 * @typedef {import('./generate.js').GenerateOptions} GenerateOptions
 * @typedef {import('./generate.js').PassphraseOptions} PassphraseOptions
 * @typedef {import('./policy.js').PolicyRules} PolicyRules
 * @typedef {import('./policy.js').PolicyResult} PolicyResult
 * @typedef {import('./policy.js').PolicyViolation} PolicyViolation
 * @typedef {import('./pepper.js').PepperConfig} PepperConfig
 * @typedef {import('./history.js').HistoryConfig} HistoryConfig
 */
