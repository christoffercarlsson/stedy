import { createFrom } from '../bytes'
import {
  ALGORITHM_ECDSA,
  CURVE25519_SIGNATURE_SIZE,
  CURVE_CURVE25519
} from './constants'
import { verifyMessage } from './curve25519'
import {
  identifyCurve,
  importSignPublicKey,
  removeKeyPrefix,
  WebCrypto
} from './utils'

const isValidSignature = (curve: string, signature: BufferSource) => {
  const sig = createFrom(signature)
  switch (curve) {
    case CURVE_CURVE25519:
      return sig.byteLength === CURVE25519_SIGNATURE_SIZE
    default:
      return sig.byteLength > 0
  }
}

const verify = async (
  crypto: WebCrypto,
  message: BufferSource,
  publicKey: BufferSource,
  signature: BufferSource,
  hash?: string
) => {
  const key = createFrom(publicKey)
  const curve = await identifyCurve(key)
  const msg = createFrom(message)
  const sig = createFrom(signature)
  if (!isValidSignature(curve, sig)) {
    return false
  }
  if (curve === CURVE_CURVE25519) {
    return verifyMessage(sig, msg, removeKeyPrefix(key))
  }
  return crypto.subtle.verify(
    { name: ALGORITHM_ECDSA, hash },
    await importSignPublicKey(crypto, curve, key),
    signature,
    msg
  )
}

export default verify
