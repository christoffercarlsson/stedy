import { split } from '../chunk.js'
import { deriveSharedSecret as deriveSecret } from '../crypto.js'
import { DH_OUTPUT_SIZE, PUBLIC_KEY_SIZE } from './constants.js'
import { importPrivateKey, importPublicKey } from './utils.js'

export const deriveSharedSecretKey = async (ourPrivateKey, theirPublicKey) =>
  deriveSecret(
    await importPrivateKey(ourPrivateKey),
    await importPublicKey(theirPublicKey),
    DH_OUTPUT_SIZE
  )

const deriveSharedSecret = async (theirKeyShare, ourPrivateKey) => {
  const [, theirPublicKey] = split(theirKeyShare, PUBLIC_KEY_SIZE)
  return deriveSharedSecretKey(ourPrivateKey, theirPublicKey)
}

export default deriveSharedSecret
