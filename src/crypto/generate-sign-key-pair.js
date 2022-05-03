import {
  ALGORITHM_ECDSA,
  ALGORITHM_NODE_ED448,
  CURVE_CURVE25519,
  CURVE_CURVE448,
  CURVE_NODE_ED448,
  KEY_USAGE_SIGN,
  KEY_USAGE_VERIFY
} from './constants.js'
import { signKeyPair } from './curve25519.js'
import { exportKeyPair, ensureSupportedCurve, addKeyPrefix } from './utils.js'

const getAlgorithm = (curve) => {
  if (curve === CURVE_CURVE448) {
    return {
      name: ALGORITHM_NODE_ED448,
      namedCurve: CURVE_NODE_ED448
    }
  }
  return {
    name: ALGORITHM_ECDSA,
    namedCurve: curve
  }
}

const generateSignKeyPair = async (crypto, curve) => {
  const crv = await ensureSupportedCurve(curve)
  if (crv === CURVE_CURVE25519) {
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
