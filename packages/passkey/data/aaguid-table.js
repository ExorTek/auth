/**
 * Curated AAGUID → device-name / vendor lookup, refreshable via
 * `scripts/refresh-aaguid-table.mjs` (which fetches the FIDO MDS3
 * BLOB, verifies it, and rewrites this file). Ship a small
 * hand-picked baseline so the offline lookup returns something
 * useful before the caller does their first MDS3 refresh.
 *
 * Sources for the initial baseline: FIDO Alliance MDS3 April-2026
 * snapshot + passkey-authenticator-aaguids (Passkey.dev community
 * list).
 */

export const AAGUID_TABLE = Object.freeze({
  // Apple platform authenticators
  'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': { name: 'iCloud Keychain (Managed)' },
  'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': { name: 'Apple Passwords' },

  // Google Password Manager
  'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': { name: 'Google Password Manager' },

  // Windows Hello
  '08987058-cadc-4b81-b6e1-30de50dcbe96': { name: 'Windows Hello Hardware Authenticator' },
  '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': { name: 'Windows Hello VBS Hardware Authenticator' },
  '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': { name: 'Windows Hello Software Authenticator' },

  // YubiKey (a handful of the most-shipped variants)
  'ee882879-721c-4913-9775-3dfcce97072a': { name: 'YubiKey 5 Series' },
  'cb69481e-8ff7-4039-93ec-0a2729a154a8': { name: 'YubiKey 5 Series (FIPS)' },
  'c1f9a0bc-1dd2-404a-b27f-8e29047a43fd': { name: 'YubiKey 5 NFC' },
  '2fc0579f-8113-47ea-b116-bb5a8db9202a': { name: 'YubiKey 5Ci' },
  'b92c3f9a-c014-4056-887f-140a2501163b': { name: 'Security Key by Yubico' },
  '149a2021-8ef6-4133-96b8-81f8d5b7f1f5': { name: 'Security Key by Yubico (FW 5.2)' },

  // Password managers / platform credential providers
  'bada5566-a7aa-401f-bd96-45619a55120d': { name: '1Password' },
  'd548826e-79b4-db40-a3d8-11116f7e8349': { name: 'Bitwarden' },
  '531126d6-e717-415c-9320-3d9aa6981239': { name: 'Dashlane' },
  '0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6': { name: 'Keeper' },
  'b84e4048-15dc-4dd0-8640-f4f60813c8af': { name: 'NordPass' },
  '53414d53-554e-4700-0000-000000000000': { name: 'Samsung Pass' },

  // Browser-embedded providers (Chromium passkeys synced to the profile)
  'adce0002-35bc-c60a-648b-0b25f1f05503': { name: 'Chrome on Mac' },
  '771b48fd-d3d4-4f74-9232-fc157ab0507a': { name: 'Edge on Mac' },
});

/** @param {string} aaguid  canonical hyphenated form */
export function lookup(aaguid) {
  return AAGUID_TABLE[aaguid] ?? null;
}
