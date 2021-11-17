import { createFrom } from '../chunk.js'
import {
  ensureSupportedKey,
  getSignAlgorithm,
  importSignPublicKey
} from './utils.js'

const verify = async (crypto, message, publicKey, signature, hash) => {
  const key = createFrom(publicKey)
  const curve = await ensureSupportedKey(key)
  return crypto.subtle.verify(
    await getSignAlgorithm(curve, hash),
    await importSignPublicKey(crypto, curve, key),
    createFrom(signature),
    createFrom(message)
  )
}

export default verify
