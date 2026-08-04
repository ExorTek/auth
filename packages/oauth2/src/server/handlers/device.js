/**
 * Device Authorization endpoint (RFC 8628 §3.1–3.2). A device with no
 * browser (CLI, TV, IoT) starts the flow here: it gets a `device_code`,
 * a short user-typed `user_code`, and a `verification_uri` to show the
 * user. The device then polls the token endpoint with the device-code
 * grant while the user approves on a second screen.
 *
 * Device-code phishing is a live 2025–2026 attack vector (an attacker
 * relays the user_code to a victim); the response carries a `warning`
 * field reminding integrators to show the user which app + scopes they
 * are approving. The two codes are unguessable CSPRNG values.
 */
import { randomBytes } from 'node:crypto';

import { isNonEmptyString } from '@exortek/shared/predicates';

import { ProtocolError, ServerError } from '../errors.js';
import { ErrorCode, OAuth2Error } from '../../internal/errors.js';
import { randomState } from '../../internal/state.js';
import { normalizeRequest } from '../request.js';
import { json, jsonError } from '../response.js';

const DEFAULT_TTL_MS = 600_000; // 10 minutes
const DEFAULT_INTERVAL_SEC = 5;
// Crockford-ish alphabet: no 0/O/1/I/L to keep the user_code unambiguous.
const USER_CODE_ALPHABET = 'BCDFGHJKMNPQRSTVWXYZ23456789';

/**
 * @param {Record<string, any>} config
 * @returns {(raw: import('../request.js').RawRequest) => Promise<import('../response.js').ServerResponse>}
 */
export function createDeviceHandler(config) {
  const ttlMs = config.deviceCodeTtlMs ?? DEFAULT_TTL_MS;
  const interval = config.deviceInterval ?? DEFAULT_INTERVAL_SEC;
  const verificationUri = config.deviceVerificationUri ?? `${config.issuer.replace(/\/$/, '')}/device`;

  return async function deviceHandler(raw) {
    try {
      const req = normalizeRequest(raw);
      if (req.method !== 'POST') {
        throw new ServerError(ProtocolError.INVALID_REQUEST, 'the device authorization endpoint only accepts POST');
      }

      // The device grant is used by public clients too, so a plain
      // client_id identifies the client (RFC 8628 §3.1).
      const clientId = req.form.client_id;
      if (!isNonEmptyString(clientId)) {
        throw new ServerError(ProtocolError.INVALID_REQUEST, 'missing client_id');
      }
      const client = await config.registry.getClient(clientId);
      if (!client) {
        throw new ServerError(ProtocolError.INVALID_CLIENT, `unknown client ${JSON.stringify(clientId)}`);
      }
      if (!client.grantTypes.includes('urn:ietf:params:oauth:grant-type:device_code')) {
        throw new ServerError(ProtocolError.UNAUTHORIZED_CLIENT, 'client may not use the device grant');
      }

      const scope = isNonEmptyString(req.form.scope) ? req.form.scope.split(/\s+/).filter(Boolean) : [];
      const deviceCode = randomState();
      const userCode = generateUserCode();

      config.stores.device.save({ deviceCode, userCode, clientId, scope, status: 'pending' }, ttlMs);

      const uriComplete = `${verificationUri}?user_code=${encodeURIComponent(userCode)}`;
      return json(200, {
        device_code: deviceCode,
        user_code: userCode,
        verification_uri: verificationUri,
        verification_uri_complete: uriComplete,
        expires_in: Math.floor(ttlMs / 1000),
        interval,
        // Not part of RFC 8628, but a loud reminder against device-code
        // phishing (never auto-approve; show app + scopes to the user).
        warning: 'display the requesting application and scopes to the user before they approve this user_code',
      });
    } catch (err) {
      if (err instanceof ServerError) {
        return jsonError(err);
      }
      throw err;
    }
  };
}

/**
 * Build the device-approval API the host application drives from its own
 * verification page: look up the pending request by `user_code`, then
 * approve (binding the authenticated user) or deny it.
 *
 * @param {Record<string, any>} config
 */
export function createDeviceApproval(config) {
  return {
    /**
     * @param {string} userCode
     * @returns {import('../stores.js').DeviceRecord | undefined}
     */
    getByUserCode(userCode) {
      return config.stores.device.getByUserCode(userCode);
    },
    /**
     * @param {string} userCode
     * @param {{ subject: string }} approval
     */
    approve(userCode, approval) {
      const record = config.stores.device.getByUserCode(userCode);
      if (!record || record.status !== 'pending') {
        throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'no pending device request for this user_code');
      }
      if (!isNonEmptyString(approval?.subject)) {
        throw new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'approve requires a subject');
      }
      config.stores.device.update(record.deviceCode, { status: 'approved', subject: approval.subject });
    },
    /**
     * @param {string} userCode
     */
    deny(userCode) {
      const record = config.stores.device.getByUserCode(userCode);
      if (record && record.status === 'pending') {
        config.stores.device.update(record.deviceCode, { status: 'denied' });
      }
    },
  };
}

/** @returns {string} an unambiguous `XXXX-XXXX` user code */
function generateUserCode() {
  // 8 unbiased characters drawn from CSPRNG bytes (32-byte source).
  const raw = randomBytes(8);
  let out = '';
  for (let i = 0; i < 8; i++) {
    out += USER_CODE_ALPHABET[raw[i] % USER_CODE_ALPHABET.length];
  }
  return `${out.slice(0, 4)}-${out.slice(4)}`;
}
