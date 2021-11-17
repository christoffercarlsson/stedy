import { createFrom } from '../chunk.js'
import { ALGORITHM_ECDH, SHARED_SECRET_DEFAULT_SIZE } from './constants.js'
import {
  ensureSupportedKey,
  importPrivateKey,
  importPublicKey
} from './utils.js'

const deriveSharedSecret = async (
  crypto,
  ourPrivateKey,
  theirPublicKey,
  size
) => {
  const privateKey = createFrom(ourPrivateKey)
  const publicKey = createFrom(theirPublicKey)
  const curve = await ensureSupportedKey(privateKey)
  return createFrom(
    await crypto.subtle.deriveBits(
      {
        name: ALGORITHM_ECDH,
        public: await importPublicKey(crypto, curve, publicKey)
      },
      await importPrivateKey(crypto, curve, privateKey),
      (Number.isInteger(size) && size > 0 ? size : SHARED_SECRET_DEFAULT_SIZE) *
        8
    )
  )
}

export default deriveSharedSecret
