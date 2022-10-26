import { createFrom } from '../../chunk.js'
import {
  ALGORITHM_ECDSA,
  ALGORITHM_NODE_ED448,
  CURVE25519_SIGNATURE_SIZE,
  CURVE448_SIGNATURE_SIZE,
  CURVE_CURVE25519,
  CURVE_CURVE448
} from '../constants.js'

const isValidSignature = (curve, signature) => {
  const sig = createFrom(signature)
  switch (curve) {
    case CURVE_CURVE25519:
      return sig.byteLength === CURVE25519_SIGNATURE_SIZE
    case CURVE_CURVE448:
      return sig.byteLength === CURVE448_SIGNATURE_SIZE
    default:
      return sig.byteLength > 0
  }
}

export const ensureValidSignature = (curve, signature) =>
  isValidSignature(curve, signature)
    ? Promise.resolve(createFrom(signature))
    : Promise.reject(new Error('Invalid signature size'))

export const getSignAlgorithm = (curve, hash) =>
  curve === CURVE_CURVE448
    ? ALGORITHM_NODE_ED448
    : { name: ALGORITHM_ECDSA, hash }

export default getSignAlgorithm
