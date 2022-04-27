import { authenticate, identify } from './autograph/authenticate.js'
import calculateSafetyNumber from './autograph/calculate-safety-number.js'
import createCertificate from './autograph/create-certificate.js'
import createSigningFunction from './autograph/create-signing-function.js'
import createTrustedParties from './autograph/create-trusted-parties.js'
import deriveSecretKey from './autograph/derive-secret-key.js'
import { generateKeyPair } from './autograph/generate-key-pair.js'
import generateKeyShare from './autograph/generate-key-share.js'
import sign from './autograph/sign.js'
import verify from './autograph/verify.js'

export {
  authenticate,
  calculateSafetyNumber,
  createCertificate,
  createSigningFunction,
  createTrustedParties,
  deriveSecretKey,
  generateKeyPair,
  generateKeyShare,
  identify,
  sign,
  verify
}
