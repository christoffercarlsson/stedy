import {
  alloc,
  concat,
  createFrom,
  equals,
  read,
  readUint16BE,
  split
} from '../chunk.js'
import { CIPHER_AES256_GCM, decrypt } from '../crypto.js'
import {
  AES_GCM_NONCE_SIZE,
  KEY_CONTEXT_INITIATOR,
  PUBLIC_KEY_SIZE,
  SIGNATURE_SIZE
} from './constants.js'
import {
  deriveKey,
  ensureValidKeyContext,
  ensureValidKeyShare,
  ensureValidSharedSecret,
  ensureValidTrustedParties,
  ensureValidTrustThreshold,
  verifyData
} from './utils.js'

const decryptMessage = async (sharedSecret, context, ciphertext, keyShare) => {
  const key = await deriveKey(sharedSecret, context)
  const nonce = alloc(AES_GCM_NONCE_SIZE)
  return decrypt(CIPHER_AES256_GCM, key, nonce, ciphertext, keyShare)
}

const parse = (ourKeyShare, theirKeyShare, message) => {
  const [, ourPublicKey] = split(ourKeyShare, PUBLIC_KEY_SIZE)
  const [theirIdentityKey] = split(theirKeyShare, PUBLIC_KEY_SIZE)
  const [signature, next] = read(message, SIGNATURE_SIZE)
  const [certificate, data] = read(
    next.subarray(2),
    readUint16BE(next) * (PUBLIC_KEY_SIZE + SIGNATURE_SIZE)
  )
  return { ourPublicKey, theirIdentityKey, signature, certificate, data }
}

const verifySignature = (ourPublicKey, theirIdentityKey, data, signature) =>
  verifyData(concat([data, ourPublicKey]), theirIdentityKey, signature)

const calculateTrustParameters = (
  trustThreshold,
  trustedParties,
  theirIdentityKey
) => {
  const identityKeys = split(trustedParties, PUBLIC_KEY_SIZE)
  return identityKeys.reduce(
    (result, identityKey) => {
      if (equals(identityKey, theirIdentityKey)) {
        return { ...result, threshold: Math.max(result.threshold - 1, 0) }
      }
      return { ...result, identityKeys: [...result.identityKeys, identityKey] }
    },
    { threshold: trustThreshold, identityKeys: [] }
  )
}

const isTrustedParty = (identityKeys, identityKey) =>
  identityKeys.length > 0 &&
  identityKeys.some((key) => equals(key, identityKey))

const findTrustedSignatures = (identityKeys, certificate) => {
  const entries = split(certificate, PUBLIC_KEY_SIZE + SIGNATURE_SIZE).map(
    (entry) => read(entry, PUBLIC_KEY_SIZE)
  )
  return entries.reduce((trustedEntries, [identityKey, signature]) => {
    if (isTrustedParty(identityKeys, identityKey)) {
      return [...trustedEntries, { identityKey, signature }]
    }
    return trustedEntries
  }, [])
}

const verifyTrust = async (
  trustThreshold,
  trustedParties,
  theirIdentityKey,
  certificate,
  theirData
) => {
  const { threshold, identityKeys } = calculateTrustParameters(
    trustThreshold,
    trustedParties,
    theirIdentityKey
  )
  const entries = findTrustedSignatures(identityKeys, certificate)
  if (entries.length < threshold) {
    return false
  }
  const data = concat([theirData, theirIdentityKey])
  const results = await Promise.all(
    entries.map(({ identityKey, signature }) =>
      verifyData(data, identityKey, signature)
    )
  )
  return results.every((result) => result === true)
}

const createResult = (identityKey, data, error = null) => ({
  data,
  error: error || null,
  identityKey,
  verified: error === null
})

const createErrorResult = (error, identityKey = null, data = null) =>
  createResult(identityKey, data, error)

const verifyResult = (
  signatureVerified,
  trustVerified,
  theirIdentityKey,
  data
) => {
  try {
    if (!signatureVerified) {
      throw new Error('Signature verification failed')
    }
    if (!trustVerified) {
      throw new Error('Trust verification failed')
    }
    return createResult(theirIdentityKey, data)
  } catch (error) {
    return createErrorResult(error, theirIdentityKey, data)
  }
}

const verifyAuthentication = async (
  trustThreshold,
  trustedParties,
  ourKeyShare,
  theirKeyShare,
  authentication,
  omitDataInTrustVerification
) => {
  const { ourPublicKey, theirIdentityKey, signature, certificate, data } =
    parse(ourKeyShare, theirKeyShare, authentication)
  const signatureVerified = await verifySignature(
    ourPublicKey,
    theirIdentityKey,
    data,
    signature
  )
  const trustVerified = await verifyTrust(
    trustThreshold,
    trustedParties,
    theirIdentityKey,
    certificate,
    omitDataInTrustVerification ? createFrom() : data
  )
  return verifyResult(
    signatureVerified === true,
    trustVerified === true,
    theirIdentityKey,
    data
  )
}

const verify = async (
  trustThreshold,
  trustedParties,
  sharedSecret,
  ourKeyShare,
  theirKeyShare,
  ciphertext,
  context = KEY_CONTEXT_INITIATOR,
  omitDataInTrustVerification = false
) => {
  try {
    const keyShare = await ensureValidKeyShare(theirKeyShare)
    const authentication = await decryptMessage(
      await ensureValidSharedSecret(sharedSecret),
      await ensureValidKeyContext(context),
      createFrom(ciphertext),
      keyShare
    )
    const result = await verifyAuthentication(
      await ensureValidTrustThreshold(trustThreshold),
      await ensureValidTrustedParties(trustedParties),
      await ensureValidKeyShare(ourKeyShare),
      keyShare,
      authentication,
      omitDataInTrustVerification === true
    )
    return result
  } catch (error) {
    return createErrorResult(error)
  }
}

export default verify
