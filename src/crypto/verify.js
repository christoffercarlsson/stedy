import { createFrom } from '../chunk.js'
import { verifyMessage } from './curve25519.js'
import {
  ensureSupportedKey,
  getSignAlgorithm,
  importSignPublicKey,
  isCurve25519Web,
  removeKeyPrefix
} from './utils.js'

const verify = async (crypto, message, publicKey, signature, hash) => {
  const key = createFrom(publicKey)
  const curve = await ensureSupportedKey(key)
  const msg = createFrom(message)
  const sig = createFrom(signature)
  if (isCurve25519Web(curve)) {
    return verifyMessage(sig, msg, removeKeyPrefix(key))
  }
  return crypto.subtle.verify(
    await getSignAlgorithm(curve, hash),
    await importSignPublicKey(crypto, curve, key),
    sig,
    msg
  )
}

export default verify
