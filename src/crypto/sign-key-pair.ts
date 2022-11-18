import {
  ALGORITHM_ECDSA,
  CURVE_CURVE25519,
  KEY_USAGE_SIGN,
  KEY_USAGE_VERIFY
} from './constants'
import { signKeyPair as ed25519KeyPair } from './curve25519'
import {
  exportKeyPair,
  ensureSupportedCurve,
  addKeyPrefix,
  WebCrypto
} from './utils'

const generateCurve25519 = async () => {
  const { publicKey, privateKey } = await ed25519KeyPair()
  return {
    publicKey: addKeyPrefix(CURVE_CURVE25519, publicKey, true, true),
    privateKey: addKeyPrefix(CURVE_CURVE25519, privateKey, true, false)
  }
}

const generateECDSA = async (crypto: WebCrypto, namedCurve: string) =>
  exportKeyPair(
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

const signKeyPair = async (crypto: WebCrypto, curve: string) => {
  const namedCurve = await ensureSupportedCurve(curve)
  return namedCurve === CURVE_CURVE25519
    ? generateCurve25519()
    : generateECDSA(crypto, namedCurve)
}

export default signKeyPair
