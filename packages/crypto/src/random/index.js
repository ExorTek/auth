import { bytes } from './bytes.js';
import { hex } from './hex.js';
import { base64url } from './base64url.js';
import { alphanumeric } from './alphanumeric.js';
import { numeric } from './numeric.js';
import { pin } from './pin.js';
import { code } from './code.js';
import { serial } from './serial.js';
import { uuid4, uuid7, uuid5, isUUID, NAMESPACE_DNS, NAMESPACE_URL, NAMESPACE_OID, NAMESPACE_X500 } from './uuid.js';
import { ulid, isULID } from './ulid.js';
import { token } from './token.js';

/**
 * Cryptographically secure random helpers.
 *
 * All members are backed by the OS CSPRNG (`node:crypto`). Re-exported as a
 * namespace object for ergonomic call sites: `random.bytes(32)`, `random.uuid4()`.
 *
 * @namespace
 */
export const random = {
  bytes,
  hex,
  base64url,
  alphanumeric,
  numeric,
  pin,
  code,
  serial,
  uuid4,
  uuid7,
  uuid5,
  isUUID,
  ulid,
  isULID,
  token,
};

export {
  bytes,
  hex,
  base64url,
  alphanumeric,
  numeric,
  pin,
  code,
  serial,
  uuid4,
  uuid7,
  uuid5,
  isUUID,
  ulid,
  isULID,
  token,
  NAMESPACE_DNS,
  NAMESPACE_URL,
  NAMESPACE_OID,
  NAMESPACE_X500,
};
