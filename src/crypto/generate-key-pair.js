import {
  ALGORITHM_ECDH,
  CURVE_CURVE25519,
  CURVE_CURVE448,
  CURVE_NODE_X448,
  CURVE_NODE_X25519,
  KEY_USAGE_DERIVE_BITS,
  KEY_USAGE_DERIVE_KEY
} from './constants.js'
import { keyPair } from './curve25519.js'
import {
  exportKeyPair,
  ensureSupportedCurve,
  addKeyPrefix,
  isCurve25519Web
} from './utils.js'

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
  const crv = await ensureSupportedCurve(curve)
  if (isCurve25519Web(crv)) {
    const { publicKey, privateKey } = await keyPair()
    return {
      publicKey: addKeyPrefix(CURVE_CURVE25519, false, true, publicKey),
      privateKey: addKeyPrefix(CURVE_CURVE25519, false, false, privateKey)
    }
  }
  const namedCurve = getNamedCurve(crv)
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
