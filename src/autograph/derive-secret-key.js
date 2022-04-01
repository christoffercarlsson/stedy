import { split } from '../chunk.js'
import { deriveSharedSecret } from '../crypto.js'
import { DH_OUTPUT_SIZE, PUBLIC_KEY_SIZE } from './constants.js'
import { importPrivateKey, importPublicKey } from './utils.js'

const deriveSecretKey = async (theirKeyShare, ourPrivateKey) => {
  const [, theirPublicKey] = split(theirKeyShare, PUBLIC_KEY_SIZE)
  return deriveSharedSecret(
    await importPrivateKey(ourPrivateKey),
    await importPublicKey(theirPublicKey),
    DH_OUTPUT_SIZE
  )
}

export default deriveSecretKey
