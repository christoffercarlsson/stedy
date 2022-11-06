import { createFrom } from '../chunk'
import { ALGORITHM_ECDSA, CURVE_CURVE25519 } from './constants'
import { verifyMessage } from './curve25519'
import {
  ensureSupportedKey,
  ensureValidSignature,
  importSignPublicKey,
  removeKeyPrefix
} from './utils'

const verify = async (crypto, message, publicKey, signature, hash) => {
  const key = createFrom(publicKey)
  const curve = await ensureSupportedKey(key)
  const msg = createFrom(message)
  const sig = await ensureValidSignature(curve, signature)
  if (curve === CURVE_CURVE25519) {
    return verifyMessage(sig, msg, removeKeyPrefix(key))
  }
  return crypto.subtle.verify(
    { name: ALGORITHM_ECDSA, hash },
    await importSignPublicKey(crypto, curve, key),
    sig,
    msg
  )
}

export default verify
