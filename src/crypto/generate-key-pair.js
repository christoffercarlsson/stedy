import {
  ALGORITHM_ECDH,
  CURVE_CURVE25519,
  KEY_USAGE_DERIVE_BITS,
  KEY_USAGE_DERIVE_KEY
} from './constants.js'
import { keyPair } from './curve25519.js'
import { exportKeyPair, ensureSupportedCurve, addKeyPrefix } from './utils.js'

const generateKeyPair = async (crypto, curve) => {
  const namedCurve = await ensureSupportedCurve(curve)
  if (namedCurve === CURVE_CURVE25519) {
    const { publicKey, privateKey } = keyPair()
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
        namedCurve
      },
      true,
      [KEY_USAGE_DERIVE_BITS, KEY_USAGE_DERIVE_KEY]
    )
  )
}

export default generateKeyPair
