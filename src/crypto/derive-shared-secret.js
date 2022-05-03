import { createFrom } from '../chunk.js'
import {
  ALGORITHM_ECDH,
  CURVE_CURVE25519,
  SHARED_SECRET_DEFAULT_SIZE
} from './constants.js'
import { scalarMult } from './curve25519.js'
import {
  ensureSupportedKey,
  importPrivateKey,
  importPublicKey,
  removeKeyPrefix
} from './utils.js'

const deriveSharedSecret = async (
  crypto,
  ourPrivateKey,
  theirPublicKey,
  size
) => {
  const privateKey = createFrom(ourPrivateKey)
  const publicKey = createFrom(theirPublicKey)
  const outputSize =
    Number.isInteger(size) && size > 0 ? size : SHARED_SECRET_DEFAULT_SIZE
  const curve = await ensureSupportedKey(privateKey)
  if (curve === CURVE_CURVE25519) {
    return (
      await scalarMult(removeKeyPrefix(privateKey), removeKeyPrefix(publicKey))
    ).subarray(0, outputSize)
  }
  return createFrom(
    await crypto.subtle.deriveBits(
      {
        name: ALGORITHM_ECDH,
        public: await importPublicKey(crypto, curve, publicKey)
      },
      await importPrivateKey(crypto, curve, privateKey),
      outputSize * 8
    )
  )
}

export default deriveSharedSecret
