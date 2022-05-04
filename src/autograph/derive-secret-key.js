import { KEY_CONTEXT_AGREEMENT } from './constants.js'
import { deriveSharedSecretKey } from './derive-shared-secret.js'
import { deriveKey } from './utils.js'
import verify from './verify.js'

const createResult = (identityKey, secretKey, error = null) => ({
  error: error || null,
  identityKey,
  secretKey,
  verified: error === null
})

const createErrorResult = (error) => createResult(null, error)

const deriveSecretKey = async (
  trustThreshold,
  trustedParties,
  ourEphemeralPrivateKey,
  sharedSecret,
  ourKeyShare,
  theirKeyShare,
  ciphertext,
  context
) => {
  try {
    const {
      data: theirEphemeralPublicKey,
      error: verificationError,
      identityKey
    } = await verify(
      trustThreshold,
      trustedParties,
      sharedSecret,
      ourKeyShare,
      theirKeyShare,
      ciphertext,
      context,
      true
    )
    if (verificationError) {
      return createErrorResult(verificationError)
    }
    const secretKey = await deriveKey(
      await deriveSharedSecretKey(
        ourEphemeralPrivateKey,
        theirEphemeralPublicKey
      ),
      KEY_CONTEXT_AGREEMENT
    )
    return createResult(identityKey, secretKey)
  } catch (error) {
    return createErrorResult(error)
  }
}

export default deriveSecretKey
