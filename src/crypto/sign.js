import { createFrom, ENCODING_PEM } from '../chunk.js'
import { signMessage } from './curve25519.js'
import {
  ensureSupportedKey,
  getSignAlgorithm,
  importSignPrivateKey,
  isCurve25519Web,
  removeKeyPrefix
} from './utils.js'

const sign = async (crypto, message, privateKey, hash) => {
  const key = createFrom(privateKey, ENCODING_PEM)
  const curve = await ensureSupportedKey(key)
  const msg = createFrom(message)
  if (isCurve25519Web(curve)) {
    return signMessage(msg, removeKeyPrefix(key))
  }
  return createFrom(
    await crypto.subtle.sign(
      await getSignAlgorithm(curve, hash),
      await importSignPrivateKey(crypto, curve, key),
      msg
    )
  )
}

export default sign
