import { authenticate, identify } from './autograph/authenticate.js'
import calculateSafetyNumber from './autograph/calculate-safety-number.js'
import {
  KEY_CONTEXT_AGREEMENT,
  KEY_CONTEXT_INITIATOR,
  KEY_CONTEXT_RESPONDER
} from './autograph/constants.js'
import createCertificate from './autograph/create-certificate.js'
import createSigningFunction from './autograph/create-signing-function.js'
import createTrustedParties from './autograph/create-trusted-parties.js'
import deriveSecretKey from './autograph/derive-secret-key.js'
import deriveSharedSecret from './autograph/derive-shared-secret.js'
import {
  generateEphemeralKeyPair,
  generateKeyPair
} from './autograph/generate-key-pair.js'
import generateKeyShare from './autograph/generate-key-share.js'
import sign from './autograph/sign.js'
import verify from './autograph/verify.js'
import verifySignature from './autograph/verify-signature.js'

export {
  KEY_CONTEXT_AGREEMENT,
  KEY_CONTEXT_INITIATOR,
  KEY_CONTEXT_RESPONDER,
  authenticate,
  calculateSafetyNumber,
  createCertificate,
  createSigningFunction,
  createTrustedParties,
  deriveSecretKey,
  deriveSharedSecret,
  generateEphemeralKeyPair,
  generateKeyPair,
  generateKeyShare,
  identify,
  sign,
  verify,
  verifySignature
}
