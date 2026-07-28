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
export declare const AAGUID_TABLE: Readonly<{
    'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': {
        name: string;
    };
    '2fc0579f-8113-47ea-b116-bb5a8db9202a': {
        name: string;
    };
    'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': {
        name: string;
    };
    'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': {
        name: string;
    };
    'd548826e-79b4-db40-a3d8-11116f7e8349': {
        name: string;
    };
    '08987058-cadc-4b81-b6e1-30de50dcbe96': {
        name: string;
    };
    '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': {
        name: string;
    };
    '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': {
        name: string;
    };
    'ee882879-721c-4913-9775-3dfcce97072a': {
        name: string;
    };
    'cb69481e-8ff7-4039-93ec-0a2729a154a8': {
        name: string;
    };
    'c1f9a0bc-1dd2-404a-b27f-8e29047a43fd': {
        name: string;
    };
    'b92c3f9a-c014-4056-887f-140a2501163b': {
        name: string;
    };
    '149a2021-8ef6-4133-96b8-81f8d5b7f1f5': {
        name: string;
    };
    'bada5566-a7aa-401f-bd96-45619a55120d': {
        name: string;
    };
    'd197a58d-4c07-4cff-8180-4e6c8fdd9c05': {
        name: string;
    };
}>;
/** @param {string} aaguid  canonical hyphenated form */
export declare function lookup(aaguid: string): any;
