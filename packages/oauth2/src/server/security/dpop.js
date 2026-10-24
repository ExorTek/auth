/**
 * DPoP — Demonstrating Proof-of-Possession (RFC 9449). A client proves it
 * holds a private key by sending a per-request `DPoP` proof JWT; the
 * server binds the issued access/refresh tokens to that key's thumbprint
 * (`cnf.jkt`), so a stolen bearer token is useless without the key. This
 * is the single biggest 2025–2026 anti-token-theft measure (FAPI 2.0,
 * open banking).
 *
 * At the token endpoint we validate the proof (type, asymmetric alg,
 * embedded public JWK, signature, `htm`/`htu`, freshness, replay) and
 * return the key thumbprint the grant binds the tokens to. A `null`
 * proof is allowed only when neither the client nor the server requires
 * DPoP — otherwise it is `invalid_dpop_proof`.
 */
import { createHash, createHmac, randomBytes } from 'node:crypto';

import { importJWK, thumbprint } from '@exortek/jwk';
import { verify as jwsVerify, decodeProtectedHeader } from '@exortek/jws';
import { encode as base64urlEncode, decode as base64urlDecode } from '@exortek/shared/base64url';
import { isNonEmptyString, isNumber, isObject } from '@exortek/shared/predicates';
import { timingSafeEqual } from '@exortek/shared/timing-safe';

import { ErrorCode, OAuth2Error } from '../../internal/errors.js';
import { ProtocolError, ServerError } from '../errors.js';
import { createReplayGuard } from './replay.js';

// RFC 9449 §4.2 — the proof `alg` must be an asymmetric JWS alg; symmetric
// and `none` are rejected so the embedded JWK is a real public key.
const ALLOWED_ALGS = new Set([
  'ES256',
  'ES384',
  'ES512',
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'EdDSA',
]);
// Proofs are single-use and short-lived; §4.3 recommends a small window.
const MAX_PROOF_AGE_MS = 60_000;

// A proof `jti` may be used once; retention covers the full freshness
// window (a proof's iat is accepted within ±MAX_PROOF_AGE_MS). The server
// passes its own replay guard (shareable across nodes via `stores.replay`);
// `verifyDpopForResource` without one falls back to this process-local guard.
const REPLAY_TTL_MS = 2 * MAX_PROOF_AGE_MS;
let defaultReplay = createReplayGuard();

// Server-provided DPoP nonce (RFC 9449 §8-9). When the server requires a
// nonce, the client must echo the most recent `DPoP-Nonce` value as the
// proof's `nonce` claim; a missing/stale nonce is answered with
// `use_dpop_nonce` and a fresh `DPoP-Nonce` header so the client retries.
//
// Nonces are stateless: `base64url(window ‖ HMAC(secret, window)[0..16])`
// for a 150 s time window, accepted for the current and the previous window.
// Every node holding the same `security.dpop.nonceSecret` issues and accepts
// the same nonces, so nonce mode works behind a load balancer with no shared
// state and nothing to sweep.
const NONCE_WINDOW_MS = 150_000;
const NONCE_MAC_BYTES = 16;

/**
 * @param {string | Uint8Array | undefined} secret   ≥ 32 bytes; random per server when omitted
 */
export function createDpopNonces(secret) {
  let key;
  if (secret === undefined) {
    key = randomBytes(32);
  } else {
    key = Buffer.from(/** @type {any} */ (secret));
    if (key.length < 32) {
      throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'security.dpop.nonceSecret must be at least 32 bytes');
    }
  }
  const mac = window => {
    const w = Buffer.alloc(4);
    w.writeUInt32BE(window);
    return Buffer.concat([w, createHmac('sha256', key).update(w).digest().subarray(0, NONCE_MAC_BYTES)]);
  };
  const currentWindow = () => Math.floor(Date.now() / NONCE_WINDOW_MS);
  return {
    issue() {
      return base64urlEncode(mac(currentWindow()));
    },
    /** @param {unknown} nonce */
    isValid(nonce) {
      if (!isNonEmptyString(nonce)) {
        return false;
      }
      let raw;
      try {
        raw = base64urlDecode(nonce);
      } catch {
        return false;
      }
      if (raw.length !== 4 + NONCE_MAC_BYTES) {
        return false;
      }
      const window = raw.readUInt32BE(0);
      const now = currentWindow();
      if (window !== now && window !== now - 1) {
        return false;
      }
      return timingSafeEqual(raw, mac(window));
    },
  };
}

/**
 * Resolve the DPoP binding for a token-endpoint request.
 *
 * @param {import('../request.js').ServerRequest} req
 * @param {Record<string, any>} config
 * @param {import('../clients.js').Client} client
 * @param {{ htu?: string }} [options]  the endpoint URL the proof must bind to (default the token endpoint)
 * @returns {Promise<{ dpopJkt: string | undefined, nonceHeaders: Record<string, string> }>}
 */
export async function resolveDpopBinding(req, config, client, options = {}) {
  const proof = req.header('dpop');
  const required = config.dpopRequired === true || client.dpopBoundAccessTokens === true;
  const nonceRequired = config.dpopNonceRequired === true;

  if (!isNonEmptyString(proof)) {
    if (required) {
      throw new ServerError(ProtocolError.INVALID_DPOP_PROOF, 'this client requires a DPoP proof');
    }
    return { dpopJkt: undefined, nonceHeaders: {} };
  }

  const { jkt, nonce } = await verifyDpopProof(proof, {
    htm: req.method,
    // The proof binds to the endpoint it was sent to — the token endpoint,
    // or the PAR endpoint for a `dpop_jkt` pre-binding (RFC 9449 §10.1).
    htu: isNonEmptyString(options.htu) ? options.htu : config.endpoints.token,
    replay: config.replay,
  });

  // RFC 9449 §8-9: when the server requires a nonce, a proof that omits it
  // or carries a stale one is answered with `use_dpop_nonce` plus a fresh
  // `DPoP-Nonce` header, and the client retries with the new value.
  if (nonceRequired && !config.dpopNonces.isValid(nonce)) {
    throw new ServerError(
      ProtocolError.USE_DPOP_NONCE,
      'a DPoP proof nonce is required; retry with the supplied nonce',
      {
        headers: { 'DPoP-Nonce': config.dpopNonces.issue() },
      },
    );
  }

  // On success, hand the client the current nonce for its next request
  // (it rotates every window, so a captured nonce ages out). Only when
  // nonces are on.
  return { dpopJkt: jkt, nonceHeaders: nonceRequired ? { 'DPoP-Nonce': config.dpopNonces.issue() } : {} };
}

/**
 * Verify a DPoP proof JWT and return its key thumbprint (`jkt`) plus the
 * `nonce` claim (if any) for the caller's nonce-challenge check.
 *
 * @param {string} proof
 * @param {{ htm: string, htu: string, ath?: string, replay?: import('./replay.js').ReplayGuard }} binding
 * @returns {Promise<{ jkt: string, nonce: string | undefined }>}
 */
export async function verifyDpopProof(proof, binding) {
  let header;
  try {
    header = decodeProtectedHeader(proof);
  } catch {
    throw new ServerError(ProtocolError.INVALID_DPOP_PROOF, 'DPoP proof is not a well-formed JWT');
  }

  if (header.typ !== 'dpop+jwt') {
    throw new ServerError(ProtocolError.INVALID_DPOP_PROOF, 'DPoP proof typ must be dpop+jwt');
  }
  if (!isNonEmptyString(header.alg) || !ALLOWED_ALGS.has(header.alg)) {
    throw new ServerError(
      ProtocolError.INVALID_DPOP_PROOF,
      `DPoP proof alg ${JSON.stringify(header.alg)} is not an accepted asymmetric algorithm`,
    );
  }
  if (!isObject(header.jwk) || isNonEmptyString(header.jwk.d)) {
    // An embedded PRIVATE key (has `d`) is a client blunder / attack.
    throw new ServerError(ProtocolError.INVALID_DPOP_PROOF, 'DPoP proof must embed a public JWK');
  }

  let key;
  let jkt;
  try {
    key = await importJWK(header.jwk);
    jkt = await thumbprint(header.jwk);
  } catch {
    throw new ServerError(ProtocolError.INVALID_DPOP_PROOF, 'DPoP proof embeds an unusable JWK');
  }

  let payload;
  try {
    ({ payload } = await jwsVerify(proof, key, { alg: [header.alg] }));
  } catch {
    throw new ServerError(ProtocolError.INVALID_DPOP_PROOF, 'DPoP proof signature is invalid');
  }

  // htm / htu bind the proof to THIS request (RFC 9449 §4.3). htu is
  // compared without query or fragment.
  if (payload.htm !== binding.htm) {
    throw new ServerError(ProtocolError.INVALID_DPOP_PROOF, 'DPoP proof htm does not match the request method');
  }
  if (normalizeHtu(payload.htu) !== normalizeHtu(binding.htu)) {
    throw new ServerError(ProtocolError.INVALID_DPOP_PROOF, 'DPoP proof htu does not match the request URI');
  }
  // At a resource server the proof must bind to the presented access token
  // via `ath` (RFC 9449 §7.1) — the base64url SHA-256 of the token.
  if (isNonEmptyString(binding.ath) && payload.ath !== binding.ath) {
    throw new ServerError(ProtocolError.INVALID_DPOP_PROOF, 'DPoP proof ath does not match the access token');
  }
  assertFresh(payload.iat);
  await assertUnique(payload.jti, binding.replay ?? defaultReplay);

  return { jkt, nonce: isNonEmptyString(payload.nonce) ? payload.nonce : undefined };
}

/**
 * Resource-server DPoP check (RFC 9449 §7). A protected resource calls
 * this with the `DPoP` proof header, the presented access token, and the
 * token's `cnf.jkt` (from the JWT claim or introspection). It verifies the
 * proof, that its `ath` binds to this exact token, and that the proving
 * key is the one the token was issued to — the missing high-level helper
 * for the resource-server half of DPoP.
 *
 * A multi-node resource server passes `replayStore` (IncrStore-shaped,
 * e.g. Redis-backed) so a proof replayed against a different node is caught.
 *
 * @param {string} proof                          the `DPoP` request header
 * @param {{ htm: string, htu: string, accessToken: string, cnfJkt: string, replayStore?: import('./replay.js').ReplayStore }} binding
 * @returns {Promise<{ jkt: string }>}
 */
export async function verifyDpopForResource(proof, binding) {
  if (!isNonEmptyString(proof)) {
    throw new ServerError(ProtocolError.INVALID_DPOP_PROOF, 'a DPoP proof is required for this token');
  }
  if (!isNonEmptyString(binding?.accessToken)) {
    throw new ServerError(ProtocolError.INVALID_DPOP_PROOF, 'verifyDpopForResource requires the access token');
  }
  const ath = base64urlEncode(createHash('sha256').update(binding.accessToken).digest());
  const replay = binding.replayStore !== undefined ? createReplayGuard(binding.replayStore) : undefined;
  const { jkt } = await verifyDpopProof(proof, { htm: binding.htm, htu: binding.htu, ath, replay });
  // The proving key must be the key the token is bound to.
  if (!isNonEmptyString(binding.cnfJkt) || jkt !== binding.cnfJkt) {
    throw new ServerError(ProtocolError.INVALID_DPOP_PROOF, 'DPoP proof key does not match the token cnf.jkt');
  }
  return { jkt };
}

/**
 * @param {unknown} htu
 * @returns {string}
 */
function normalizeHtu(htu) {
  if (!isNonEmptyString(htu)) {
    return '';
  }
  try {
    const url = new URL(htu);
    url.hash = '';
    url.search = '';
    return url.href;
  } catch {
    return htu;
  }
}

/** @param {unknown} iat */
function assertFresh(iat) {
  if (!isNumber(iat)) {
    throw new ServerError(ProtocolError.INVALID_DPOP_PROOF, 'DPoP proof is missing iat');
  }
  const ageMs = Date.now() - iat * 1000;
  if (ageMs > MAX_PROOF_AGE_MS || ageMs < -MAX_PROOF_AGE_MS) {
    throw new ServerError(ProtocolError.INVALID_DPOP_PROOF, 'DPoP proof iat is outside the acceptable window');
  }
}

/**
 * @param {unknown} jti
 * @param {import('./replay.js').ReplayGuard} replay
 */
async function assertUnique(jti, replay) {
  if (!isNonEmptyString(jti)) {
    throw new ServerError(ProtocolError.INVALID_DPOP_PROOF, 'DPoP proof is missing jti');
  }
  if (await replay.seen('dpop', jti, REPLAY_TTL_MS)) {
    throw new ServerError(ProtocolError.INVALID_DPOP_PROOF, 'DPoP proof jti has already been used (replay)');
  }
}

/** Test hook — reset the process-local fallback replay guard. */
export function _clearDpopReplayCache() {
  defaultReplay = createReplayGuard();
}
