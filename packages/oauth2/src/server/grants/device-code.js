/**
 * Device Authorization Grant — the token-endpoint half (RFC 8628 §3.4).
 * The device polls with its `device_code`; while the user has not yet
 * approved, the server answers `authorization_pending` (or `slow_down` if
 * the device polls faster than the advertised interval). Once approved
 * the code is redeemed exactly once for tokens; a denied or expired
 * request returns the matching error.
 */
import { isNonEmptyString, isNumber } from '@exortek/shared/predicates';

import { ProtocolError, ServerError } from '../errors.js';
import { buildAccessResponse, refreshAllowed, mintRefreshToken } from './_issue.js';

const DEFAULT_INTERVAL_MS = 5000;

/**
 * @param {import('../request.js').ServerRequest} req
 * @param {{ config: Record<string, any>, client: import('../clients.js').Client, dpopJkt?: string }} ctx
 * @returns {Promise<Record<string, unknown>>}
 */
export async function deviceCodeGrant(req, ctx) {
  const { config, client } = ctx;

  if (!client.grantTypes.includes('urn:ietf:params:oauth:grant-type:device_code')) {
    throw new ServerError(ProtocolError.UNAUTHORIZED_CLIENT, 'client may not use the device grant');
  }

  const deviceCode = req.form.device_code;
  if (!isNonEmptyString(deviceCode)) {
    throw new ServerError(ProtocolError.INVALID_REQUEST, 'missing device_code');
  }

  const record = await config.stores.device.getByDeviceCode(deviceCode);
  if (!record) {
    // Absent = expired-and-evicted or never issued (RFC 8628 §3.5).
    throw new ServerError(ProtocolError.EXPIRED_TOKEN, 'the device_code is expired or unknown');
  }
  if (record.clientId !== client.clientId) {
    throw new ServerError(ProtocolError.INVALID_GRANT, 'device_code was issued to a different client');
  }

  // Rate-limit polling: a device that polls faster than the interval gets
  // `slow_down` and must add 5s to its interval (RFC 8628 §3.5).
  const now = Date.now();
  const intervalMs = isNumber(config.deviceInterval) ? config.deviceInterval * 1000 : DEFAULT_INTERVAL_MS;
  if (isNumber(record.lastPolledAt) && now - record.lastPolledAt < intervalMs) {
    await config.stores.device.update(deviceCode, { lastPolledAt: now });
    throw new ServerError(ProtocolError.SLOW_DOWN, 'polling too fast; increase the interval by 5 seconds');
  }
  await config.stores.device.update(deviceCode, { lastPolledAt: now });

  if (record.status === 'denied') {
    throw new ServerError(ProtocolError.ACCESS_DENIED, 'the user denied the device authorization request');
  }
  if (record.status === 'redeemed') {
    // The device_code was already exchanged for tokens — a second
    // redemption is invalid (single-use, RFC 8628 §3.5).
    throw new ServerError(ProtocolError.INVALID_GRANT, 'the device_code has already been used');
  }
  if (record.status !== 'approved') {
    // Still 'pending'.
    throw new ServerError(ProtocolError.AUTHORIZATION_PENDING, 'the user has not yet approved the request');
  }
  if (!isNonEmptyString(record.subject)) {
    throw new ServerError(ProtocolError.AUTHORIZATION_PENDING, 'the device request is not fully approved');
  }

  // Redeem once: flip to a terminal state so a repeat poll can't re-issue.
  await config.stores.device.update(deviceCode, { status: 'redeemed' });

  const body = await buildAccessResponse(config, {
    subject: record.subject,
    clientId: client.clientId,
    scope: record.scope,
    dpopJkt: ctx.dpopJkt,
  });

  if (refreshAllowed(config, client)) {
    body.refresh_token = await mintRefreshToken(config, {
      subject: record.subject,
      clientId: client.clientId,
      scope: record.scope,
      dpopJkt: ctx.dpopJkt,
    });
  }

  return body;
}
