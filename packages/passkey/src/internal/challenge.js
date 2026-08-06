/**
 * Thin wrapper around `@exortek/challenge` that maps the
 * challenge-lib's compact token payload onto the WebAuthn
 * `challenge` value.
 *
 * The challenge library issues a signed compact token
 * `<prefix>.<payload_b64u>.<mac_b64u>` whose payload includes a
 * random `jti` (128 bits). WebAuthn's spec (§5.4.4) requires the
 * `challenge` field to carry ≥ 128 random bits, base64url-encoded
 * in the options JSON. We reuse the `jti` — no separate randomness
 * needed, single-use / TTL / method-step binding come for free
 * from the challenge library.
 */

import { base64url } from '@exortek/crypto/encode';
import { createChallenge, verifyChallenge } from '@exortek/challenge';
import { PasskeyError, ErrorCode } from '../errors.js';

/**
 * Decode a challenge-lib token's payload without verifying the MAC.
 * We only use this at `begin` time — the token was just minted, so
 * we can trust ourselves. Verification happens at `finish` time via
 * `verifyChallenge`.
 *
 * @param {string} token
 * @returns {{ jti: string }}
 */
export function readIssuedJti(token) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new PasskeyError(
      ErrorCode.CHALLENGE_INVALID,
      'passkey: challenge token has wrong shape (expected <prefix>.<payload>.<mac>)',
    );
  }
  let payload;
  try {
    const raw = new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(base64url.decode(parts[1])));
    payload = JSON.parse(raw);
  } catch (err) {
    throw new PasskeyError(
      ErrorCode.CHALLENGE_INVALID,
      `passkey: challenge token payload not decodable (${err.message})`,
    );
  }
  if (!payload || typeof payload.jti !== 'string' || payload.jti.length === 0) {
    throw new PasskeyError(ErrorCode.CHALLENGE_INVALID, 'passkey: challenge token payload missing jti');
  }
  return { jti: payload.jti };
}

/**
 * Issue a challenge for a passkey flow. Returns the compact token
 * (the app hands this back at `finish`) and the base64url challenge
 * value the browser will echo in `clientDataJSON`.
 *
 * @param {object} options
 * @param {string | Buffer} options.secret
 * @param {import('@exortek/challenge').IncrStore} options.store
 * @param {string} options.step        `'register'` | `'authenticate'`
 * @param {string} [options.userId]
 * @param {string | number} [options.expiresIn=300_000]  challenge TTL
 * @param {string} [options.prefix]
 * @returns {Promise<{ challengeToken: string, challengeBase64Url: string }>}
 */
export async function issuePasskeyChallenge(options) {
  const { secret, store, step, userId, expiresIn = 5 * 60_000, prefix } = options;
  const challengeToken = await createChallenge({
    secret,
    method: 'passkey',
    step,
    userId,
    expiresIn,
    singleUse: true,
    store,
    prefix,
  });
  const { jti } = readIssuedJti(challengeToken);
  return { challengeToken, challengeBase64Url: jti };
}

/**
 * Verify a challenge token and confirm it matches the challenge
 * carried in `clientDataJSON`.
 *
 * @param {object} options
 * @param {string} options.challengeToken
 * @param {string} options.challengeBase64UrlFromClient
 * @param {string | Buffer} options.secret
 * @param {import('@exortek/challenge').IncrStore} options.store
 * @param {string} options.step
 * @param {string} [options.userId]
 * @param {string} [options.prefix]
 * @returns {Promise<void>}
 */
export async function consumePasskeyChallenge(options) {
  const { challengeToken, challengeBase64UrlFromClient, secret, store, step, userId, prefix } = options;
  const result = await verifyChallenge(challengeToken, {
    secret,
    consume: true,
    store,
    expectedMethod: 'passkey',
    expectedStep: step,
    expectedUserId: userId,
    prefix,
  });
  if (!result.valid) {
    if (result.reason === 'expired') {
      throw new PasskeyError(ErrorCode.CHALLENGE_EXPIRED, `passkey: challenge expired`);
    }
    if (result.reason === 'replay') {
      throw new PasskeyError(ErrorCode.CHALLENGE_ALREADY_USED, `passkey: challenge already used`);
    }
    throw new PasskeyError(ErrorCode.CHALLENGE_INVALID, `passkey: challenge verify failed (${result.reason})`);
  }
  if (result.payload.jti !== challengeBase64UrlFromClient) {
    throw new PasskeyError(
      ErrorCode.CHALLENGE_MISMATCH,
      `passkey: challenge in clientDataJSON does not match issued challenge`,
    );
  }
}
