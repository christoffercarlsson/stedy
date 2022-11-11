import { createFrom, ENCODING_PEM } from '../bytes'
import { ALGORITHM_ECDSA, CURVE_CURVE25519 } from './constants'
import { signMessage } from './curve25519'
import {
  identifyCurve,
  importSignPrivateKey,
  removeKeyPrefix,
  WebCrypto
} from './utils'

const sign = async (
  crypto: WebCrypto,
  message: BufferSource,
  privateKey: BufferSource,
  hash?: string
) => {
  const key = createFrom(privateKey, ENCODING_PEM)
  const curve = await identifyCurve(key)
  const msg = createFrom(message)
  if (curve === CURVE_CURVE25519) {
    return signMessage(msg, removeKeyPrefix(key))
  }
  return createFrom(
    await crypto.subtle.sign(
      { name: ALGORITHM_ECDSA, hash },
      await importSignPrivateKey(crypto, curve, key),
      msg
    )
  )
}

export default sign
