import {
  ALGORITHM_ECDH,
  CURVE_CURVE25519,
  CURVE_CURVE448,
  CURVE_NODE_X448,
  KEY_USAGE_DERIVE_BITS,
  KEY_USAGE_DERIVE_KEY
} from './constants.js'
import { keyPair } from './curve25519.js'
import { exportKeyPair, ensureSupportedCurve, addKeyPrefix } from './utils.js'

const generateKeyPair = async (crypto, curve) => {
  const crv = await ensureSupportedCurve(curve)
  if (crv === CURVE_CURVE25519) {
    const { publicKey, privateKey } = await keyPair()
    return {
      publicKey: addKeyPrefix(CURVE_CURVE25519, false, true, publicKey),
      privateKey: addKeyPrefix(CURVE_CURVE25519, false, false, privateKey)
    }
  }
  return exportKeyPair(
    crypto,
    await crypto.subtle.generateKey(
      {
        name: ALGORITHM_ECDH,
        namedCurve: crv === CURVE_CURVE448 ? CURVE_NODE_X448 : crv
      },
      true,
      [KEY_USAGE_DERIVE_BITS, KEY_USAGE_DERIVE_KEY]
    )
  )
}

export default generateKeyPair
