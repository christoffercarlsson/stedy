import {
  ALGORITHM_ECDSA,
  CURVE_CURVE25519,
  KEY_USAGE_SIGN,
  KEY_USAGE_VERIFY
} from './constants'
import { signKeyPair } from './curve25519'
import {
  exportKeyPair,
  ensureSupportedCurve,
  addKeyPrefix,
  WebCrypto
} from './utils'

const generateSignKeyPair = async (crypto: WebCrypto, curve: string) => {
  const namedCurve = await ensureSupportedCurve(curve)
  if (namedCurve === CURVE_CURVE25519) {
    const { publicKey, privateKey } = await signKeyPair()
    return {
      publicKey: addKeyPrefix(CURVE_CURVE25519, true, true, publicKey),
      privateKey: addKeyPrefix(CURVE_CURVE25519, true, false, privateKey)
    }
  }
  return exportKeyPair(
    crypto,
    await crypto.subtle.generateKey(
      {
        name: ALGORITHM_ECDSA,
        namedCurve
      },
      true,
      [KEY_USAGE_SIGN, KEY_USAGE_VERIFY]
    )
  )
}

export default generateSignKeyPair
