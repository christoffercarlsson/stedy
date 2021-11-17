import { createFrom, ENCODING_PEM } from '../chunk.js'
import {
  ensureSupportedKey,
  getSignAlgorithm,
  importSignPrivateKey
} from './utils.js'

const sign = async (crypto, message, privateKey, hash) => {
  const key = createFrom(privateKey, ENCODING_PEM)
  const curve = await ensureSupportedKey(key)
  return createFrom(
    await crypto.subtle.sign(
      await getSignAlgorithm(curve, hash),
      await importSignPrivateKey(crypto, curve, key),
      createFrom(message)
    )
  )
}

export default sign
