import { BaseError } from '@exortek/shared/errors';

export const ErrorCode = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',

  // Challenge lifecycle
  CHALLENGE_MISMATCH: 'CHALLENGE_MISMATCH',
  CHALLENGE_EXPIRED: 'CHALLENGE_EXPIRED',
  CHALLENGE_ALREADY_USED: 'CHALLENGE_ALREADY_USED',
  CHALLENGE_INVALID: 'CHALLENGE_INVALID',

  // Client / authenticator data checks
  ORIGIN_MISMATCH: 'ORIGIN_MISMATCH',
  RP_ID_MISMATCH: 'RP_ID_MISMATCH',
  CLIENT_DATA_INVALID: 'CLIENT_DATA_INVALID',
  AUTH_DATA_INVALID: 'AUTH_DATA_INVALID',
  USER_VERIFICATION_REQUIRED: 'USER_VERIFICATION_REQUIRED',
  USER_PRESENCE_REQUIRED: 'USER_PRESENCE_REQUIRED',
  BACKUP_ELIGIBLE_REQUIRED: 'BACKUP_ELIGIBLE_REQUIRED',
  BACKED_UP_REQUIRED: 'BACKED_UP_REQUIRED',

  // Signature / crypto
  SIGNATURE_INVALID: 'SIGNATURE_INVALID',
  COUNTER_ROLLBACK: 'COUNTER_ROLLBACK',
  PUBLIC_KEY_UNSUPPORTED: 'PUBLIC_KEY_UNSUPPORTED',
  UNSUPPORTED_ALGORITHM: 'UNSUPPORTED_ALGORITHM',

  // Attestation
  ATTESTATION_INVALID: 'ATTESTATION_INVALID',
  ATTESTATION_TRUST_ANCHOR_MISSING: 'ATTESTATION_TRUST_ANCHOR_MISSING',
  ATTESTATION_CERT_REVOKED: 'ATTESTATION_CERT_REVOKED',
  UNSUPPORTED_ATTESTATION_FORMAT: 'UNSUPPORTED_ATTESTATION_FORMAT',

  // Extensions / MDS
  EXTENSION_INVALID: 'EXTENSION_INVALID',
  MDS_BLOB_INVALID: 'MDS_BLOB_INVALID',
});

export class PasskeyError extends BaseError {
  static statuses = {
    [ErrorCode.INVALID_ARGUMENT]: 400,
    [ErrorCode.CHALLENGE_MISMATCH]: 400,
    [ErrorCode.CHALLENGE_EXPIRED]: 400,
    [ErrorCode.CHALLENGE_ALREADY_USED]: 400,
    [ErrorCode.CHALLENGE_INVALID]: 400,
    [ErrorCode.ORIGIN_MISMATCH]: 400,
    [ErrorCode.RP_ID_MISMATCH]: 400,
    [ErrorCode.CLIENT_DATA_INVALID]: 400,
    [ErrorCode.AUTH_DATA_INVALID]: 400,
    [ErrorCode.USER_VERIFICATION_REQUIRED]: 400,
    [ErrorCode.USER_PRESENCE_REQUIRED]: 400,
    [ErrorCode.BACKUP_ELIGIBLE_REQUIRED]: 400,
    [ErrorCode.BACKED_UP_REQUIRED]: 400,
    [ErrorCode.SIGNATURE_INVALID]: 400,
    [ErrorCode.COUNTER_ROLLBACK]: 400,
    [ErrorCode.PUBLIC_KEY_UNSUPPORTED]: 400,
    [ErrorCode.UNSUPPORTED_ALGORITHM]: 400,
    [ErrorCode.ATTESTATION_INVALID]: 400,
    [ErrorCode.ATTESTATION_TRUST_ANCHOR_MISSING]: 400,
    [ErrorCode.ATTESTATION_CERT_REVOKED]: 400,
    [ErrorCode.UNSUPPORTED_ATTESTATION_FORMAT]: 400,
    [ErrorCode.EXTENSION_INVALID]: 400,
    [ErrorCode.MDS_BLOB_INVALID]: 400,
  };
  static defaultStatus = 500;
}

// Factory helpers — every ErrorCode has one to enforce
// "no dead codes" per feedback_error_code_must_actually_throw.
const factory = code => (message, options) => new PasskeyError(code, message, options);
const throwFactory = code => (message, options) => {
  throw new PasskeyError(code, message, options);
};

export const throwInvalidArgument = throwFactory(ErrorCode.INVALID_ARGUMENT);
export const throwChallengeMismatch = throwFactory(ErrorCode.CHALLENGE_MISMATCH);
export const throwChallengeExpired = throwFactory(ErrorCode.CHALLENGE_EXPIRED);
export const throwChallengeAlreadyUsed = throwFactory(ErrorCode.CHALLENGE_ALREADY_USED);
export const throwChallengeInvalid = throwFactory(ErrorCode.CHALLENGE_INVALID);
export const throwOriginMismatch = throwFactory(ErrorCode.ORIGIN_MISMATCH);
export const throwRpIdMismatch = throwFactory(ErrorCode.RP_ID_MISMATCH);
export const throwClientDataInvalid = throwFactory(ErrorCode.CLIENT_DATA_INVALID);
export const throwAuthDataInvalid = throwFactory(ErrorCode.AUTH_DATA_INVALID);
export const throwUserVerificationRequired = throwFactory(ErrorCode.USER_VERIFICATION_REQUIRED);
export const throwUserPresenceRequired = throwFactory(ErrorCode.USER_PRESENCE_REQUIRED);
export const throwBackupEligibleRequired = throwFactory(ErrorCode.BACKUP_ELIGIBLE_REQUIRED);
export const throwBackedUpRequired = throwFactory(ErrorCode.BACKED_UP_REQUIRED);
export const throwSignatureInvalid = throwFactory(ErrorCode.SIGNATURE_INVALID);
export const throwCounterRollback = throwFactory(ErrorCode.COUNTER_ROLLBACK);
export const throwPublicKeyUnsupported = throwFactory(ErrorCode.PUBLIC_KEY_UNSUPPORTED);
export const throwUnsupportedAlgorithm = throwFactory(ErrorCode.UNSUPPORTED_ALGORITHM);
export const throwAttestationInvalid = throwFactory(ErrorCode.ATTESTATION_INVALID);
export const throwAttestationTrustAnchorMissing = throwFactory(ErrorCode.ATTESTATION_TRUST_ANCHOR_MISSING);
export const throwAttestationCertRevoked = throwFactory(ErrorCode.ATTESTATION_CERT_REVOKED);
export const throwUnsupportedAttestationFormat = throwFactory(ErrorCode.UNSUPPORTED_ATTESTATION_FORMAT);
export const throwExtensionInvalid = throwFactory(ErrorCode.EXTENSION_INVALID);
export const throwMdsBlobInvalid = throwFactory(ErrorCode.MDS_BLOB_INVALID);

// Non-throwing constructors, for cases where the caller needs to
// attach a `cause` / `details` before throwing.
export const invalidArgument = factory(ErrorCode.INVALID_ARGUMENT);
