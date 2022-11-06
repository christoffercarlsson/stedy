import { createFrom } from '../../chunk'
import { CURVE25519_SIGNATURE_SIZE, CURVE_CURVE25519 } from '../constants'

const isValidSignature = (curve, signature) => {
  const sig = createFrom(signature)
  switch (curve) {
    case CURVE_CURVE25519:
      return sig.byteLength === CURVE25519_SIGNATURE_SIZE
    default:
      return sig.byteLength > 0
  }
}

const ensureValidSignature = (curve, signature) =>
  isValidSignature(curve, signature)
    ? Promise.resolve(createFrom(signature))
    : Promise.reject(new Error('Invalid signature size'))

export default ensureValidSignature
