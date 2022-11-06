import { createFrom, ENCODING_PEM } from '../chunk'
import { ALGORITHM_ECDSA, CURVE_CURVE25519 } from './constants'
import { signMessage } from './curve25519'
import {
  ensureSupportedKey,
  importSignPrivateKey,
  removeKeyPrefix
} from './utils'

const sign = async (crypto, message, privateKey, hash) => {
  const key = createFrom(privateKey, ENCODING_PEM)
  const curve = await ensureSupportedKey(key)
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
