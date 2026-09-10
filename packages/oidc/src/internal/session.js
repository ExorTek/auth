/**
 * OpenID Connect **Session Management 1.0** helpers.
 *
 * The OP tracks login state in a browser-scoped value (the "OP browser
 * state", an opaque cookie the OP sets and rotates on login/logout). It
 * derives a `session_state` from that value, the client id and the RP's
 * origin, and returns it to the RP. The RP renders a hidden iframe pointing
 * at the OP's `check_session_iframe`; a `postMessage` handshake lets the RP
 * poll whether the OP session changed — all without a network round-trip.
 *
 * This module owns the two server-side pieces: computing `session_state`
 * (§4.2) and rendering the OP iframe document (§4.2, the calculation the
 * iframe re-runs in the browser).
 */
import { createHash, randomBytes } from 'node:crypto';

import { encode as base64urlEncode } from '@exortek/shared/base64url';

/**
 * Compute a `session_state` value (OIDC Session Management §4.2):
 * `base64url(sha256(client_id + " " + origin + " " + op_browser_state + " " +
 * salt)) + "." + salt`.
 *
 * @param {{ clientId: string, origin: string, opBrowserState: string, salt?: string }} input
 * @returns {string}
 */
export function computeSessionState(input) {
  const salt = input.salt ?? base64urlEncode(randomBytes(8));
  const material = `${input.clientId} ${input.origin} ${input.opBrowserState} ${salt}`;
  const hash = base64urlEncode(createHash('sha256').update(material).digest());
  return `${hash}.${salt}`;
}

/**
 * Render the OP `check_session_iframe` document. The script re-runs the
 * §4.2 calculation in the browser on each `postMessage` and replies
 * `unchanged` / `changed` / `error`. The OP browser state is read from the
 * cookie named `cookieName`.
 *
 * @param {{ cookieName?: string }} [options]
 * @returns {string}  a complete HTML document
 */
export function checkSessionIframeHtml(options = {}) {
  const cookieName = options.cookieName ?? 'op_browser_state';
  // The cookie name is the only injected value; JSON.stringify keeps it a safe
  // string literal inside the script.
  const cookieLiteral = JSON.stringify(cookieName);
  return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>check_session_iframe</title></head>
<body>
<script>
(function () {
  var COOKIE_NAME = ${cookieLiteral};

  function opBrowserState() {
    var match = document.cookie.match(new RegExp('(?:^|; )' + COOKIE_NAME + '=([^;]*)'));
    return match ? decodeURIComponent(match[1]) : '';
  }

  function b64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var str = '';
    for (var i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
    return btoa(str).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  }

  async function computeSessionState(clientId, origin, salt) {
    var material = clientId + ' ' + origin + ' ' + opBrowserState() + ' ' + salt;
    var digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(material));
    return b64url(digest) + '.' + salt;
  }

  window.addEventListener('message', async function (e) {
    var reply = function (status) { e.source.postMessage(status, e.origin); };
    try {
      var parts = String(e.data).split(' ');
      var clientId = parts[0];
      var sessionState = parts[1];
      if (!clientId || !sessionState) return reply('error');
      var salt = sessionState.split('.')[1];
      var expected = await computeSessionState(clientId, e.origin, salt);
      reply(sessionState === expected ? 'unchanged' : 'changed');
    } catch (err) {
      reply('error');
    }
  }, false);
})();
</script>
</body>
</html>`;
}
