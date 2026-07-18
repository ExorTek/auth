/**
 * `base64url` codec — RFC 4648 §5. Wraps the shared implementation so
 * failures surface as typed `JwtError` for the package's public API.
 */

import * as sb from '@exortek/shared/base64url';
import { JwtError, ErrorCode } from './errors.js';

export function encode(bytes) {
  try {
    return sb.encode(bytes);
  } catch (err) {
    throw new JwtError(ErrorCode.INVALID_ARGUMENT, err.message);
  }
}

export function encodeString(text) {
  try {
    return sb.encodeString(text);
  } catch (err) {
    throw new JwtError(ErrorCode.INVALID_ARGUMENT, err.message);
  }
}

export function encodeJson(value) {
  return sb.encodeJson(value);
}

export function decode(text) {
  try {
    return sb.decode(text);
  } catch (err) {
    throw new JwtError(ErrorCode.INVALID_TOKEN, err.message);
  }
}

export function decodeToString(text) {
  try {
    return sb.decodeToString(text);
  } catch (err) {
    throw new JwtError(ErrorCode.INVALID_TOKEN, err.message);
  }
}

export function decodeJson(text) {
  try {
    return sb.decodeJson(text);
  } catch (err) {
    throw new JwtError(ErrorCode.INVALID_TOKEN, err.message);
  }
}
