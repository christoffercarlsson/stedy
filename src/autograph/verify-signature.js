import { concat, createFrom, read } from '../chunk.js'
import { KEY_CONTEXT_RESPONDER, PUBLIC_KEY_SIZE } from './constants.js'
import { verifyData } from './utils.js'
import verify from './verify.js'

const createResult = (identityKey, signature = null, error = null) => ({
  error: error || null,
  identityKey,
  signature,
  verified: error === null
})

const createErrorResult = (error, identityKey = null, signature = null) =>
  createResult(identityKey, signature, error)

const verifySignature = async (
  trustThreshold,
  trustedParties,
  ourData,
  sharedSecret,
  ourKeyShare,
  theirKeyShare,
  ciphertext
) => {
  try {
    const {
      data: signature,
      error: verificationError,
      identityKey
    } = await verify(
      trustThreshold,
      trustedParties,
      sharedSecret,
      ourKeyShare,
      theirKeyShare,
      ciphertext,
      KEY_CONTEXT_RESPONDER,
      true
    )
    if (verificationError) {
      return createErrorResult(verificationError)
    }
    const [ourIdentityKey] = read(ourKeyShare, PUBLIC_KEY_SIZE)
    const verified = await verifyData(
      concat([createFrom(ourData), createFrom(ourIdentityKey)]),
      identityKey,
      signature
    )
    if (!verified) {
      return createErrorResult(new Error('Signature verification failed'))
    }
    return createResult(identityKey, signature)
  } catch (error) {
    return createErrorResult(error)
  }
}

export default verifySignature
