import { concat } from '../chunk.js'
import { generateEphemeralKeyPair } from './generate-key-pair.js'
import { ensureValidPublicKey } from './utils.js'

const generateKeyShare = async (ourIdentityPublicKey) => {
  const keyPair = await generateEphemeralKeyPair()
  const keyShare = concat([
    await ensureValidPublicKey(ourIdentityPublicKey),
    keyPair.publicKey
  ])
  return [keyShare, keyPair.privateKey]
}

export default generateKeyShare
