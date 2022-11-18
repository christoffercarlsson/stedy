import {
  ALGORITHM_ECDH,
  CURVE_CURVE25519,
  KEY_USAGE_DERIVE_BITS,
  KEY_USAGE_DERIVE_KEY
} from './constants'
import { keyPair as x25519KeyPair } from './curve25519'
import {
  exportKeyPair,
  ensureSupportedCurve,
  addKeyPrefix,
  WebCrypto
} from './utils'

const generateCurve25519 = () => {
  const { publicKey, privateKey } = x25519KeyPair()
  return {
    publicKey: addKeyPrefix(CURVE_CURVE25519, publicKey, false, true),
    privateKey: addKeyPrefix(CURVE_CURVE25519, privateKey, false, false)
  }
}

const generateECDH = async (crypto: WebCrypto, namedCurve: string) =>
  exportKeyPair(
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

const keyPair = async (crypto: WebCrypto, curve: string) => {
  const namedCurve = await ensureSupportedCurve(curve)
  return namedCurve === CURVE_CURVE25519
    ? generateCurve25519()
    : generateECDH(crypto, namedCurve)
}

export default keyPair
