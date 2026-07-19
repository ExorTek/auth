/**
 * Bias-free rejection sampling — thin re-export of the shared
 * primitive. Kept here so existing callers (crypto/random/*) can
 * import the same name they always did without a churn commit.
 */

export { sampleAlphabet as biasFreeSample } from '@exortek/shared/sample';
