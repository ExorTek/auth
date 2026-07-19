// PHC strings use unpadded base64 — thin re-export of the shared
// codec so the same names (`b64Encode` / `b64Decode`) stay usable
// across the algorithm files (argon2, scrypt, pbkdf2, phc.js).

export { encode as b64Encode, decode as b64Decode } from '@exortek/shared/base64';
