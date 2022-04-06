import {
  ALGORITHM_ECDSA,
  ALGORITHM_NODE_ED25519,
  ALGORITHM_NODE_ED448,
  CURVE_CURVE25519,
  CURVE_CURVE448,
  CURVE_NODE_ED25519,
  CURVE_NODE_ED448,
  KEY_USAGE_SIGN,
  KEY_USAGE_VERIFY
} from './constants.js'
import { signKeyPair } from './curve25519.js'
import {
  exportKeyPair,
  ensureSupportedCurve,
  addKeyPrefix,
  isCurve25519Web
} from './utils.js'

const getAlgorithm = (curve) => {
  switch (curve) {
    case CURVE_CURVE448:
      return {
        name: ALGORITHM_NODE_ED448,
        namedCurve: CURVE_NODE_ED448
      }
    case CURVE_CURVE25519:
      return {
        name: ALGORITHM_NODE_ED25519,
        namedCurve: CURVE_NODE_ED25519
      }
    default:
      return {
        name: ALGORITHM_ECDSA,
        namedCurve: curve
      }
  }
}

const generateSignKeyPair = async (crypto, curve) => {
  const crv = await ensureSupportedCurve(curve)
  if (isCurve25519Web(crv)) {
    const { publicKey, privateKey } = await signKeyPair()
    return {
      publicKey: addKeyPrefix(CURVE_CURVE25519, true, true, publicKey),
      privateKey: addKeyPrefix(CURVE_CURVE25519, true, false, privateKey)
    }
  }
  return exportKeyPair(
    crypto,
    await crypto.subtle.generateKey(getAlgorithm(crv), true, [
      KEY_USAGE_SIGN,
      KEY_USAGE_VERIFY
    ])
  )
}

export default generateSignKeyPair
