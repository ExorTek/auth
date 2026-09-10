// @exortek/auth — umbrella. Re-exports every package as a namespace, and
// forwards every subpath under a matching path (see package.json exports).
// Namespace form:  import { jwt, otp } from '@exortek/auth'
// Subpath form:    import { fastify } from '@exortek/auth/jwt/fastify'

export * as crypto from '@exortek/crypto';
export * as jwk from '@exortek/jwk';
export * as jws from '@exortek/jws';
export * as jwt from '@exortek/jwt';
export * as jwe from '@exortek/jwe';
export * as jwks from '@exortek/jwks';
export * as opaque from '@exortek/opaque';
export * as paseto from '@exortek/paseto';
export * as password from '@exortek/password';
export * as otp from '@exortek/otp';
export * as challenge from '@exortek/challenge';
export * as magicLink from '@exortek/magic-link';
export * as passkey from '@exortek/passkey';
export * as session from '@exortek/session';
export * as security from '@exortek/security';
export * as ua from '@exortek/ua';
export * as apiKey from '@exortek/apikey';
export * as oauth2 from '@exortek/oauth2';
export * as oidc from '@exortek/oidc';
