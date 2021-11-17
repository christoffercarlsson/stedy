import {
  ALGORITHM_ECDH,
  CURVE_CURVE25519,
  CURVE_CURVE448,
  CURVE_NODE_X448,
  CURVE_NODE_X25519,
  KEY_USAGE_DERIVE_BITS,
  KEY_USAGE_DERIVE_KEY
} from './constants.js'
import { exportKeyPair, ensureSupportedCurve } from './utils.js'

const getNamedCurve = (curve) => {
  if (curve === CURVE_CURVE448) {
    return CURVE_NODE_X448
  }
  if (curve === CURVE_CURVE25519) {
    return CURVE_NODE_X25519
  }
  return curve
}

const generateKeyPair = async (crypto, curve) => {
  const namedCurve = getNamedCurve(await ensureSupportedCurve(curve))
  return exportKeyPair(
    crypto,
    await crypto.subtle.generateKey(
      { name: ALGORITHM_ECDH, namedCurve },
      true,
      [KEY_USAGE_DERIVE_BITS, KEY_USAGE_DERIVE_KEY]
    )
  )
}

export default generateKeyPair
