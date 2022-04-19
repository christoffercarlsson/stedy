import {
  alloc,
  append,
  concat,
  createFrom,
  split,
  writeUint16BE
} from '../chunk.js'
import { CIPHER_AES256_GCM, encrypt } from '../crypto.js'
import {
  AES_GCM_NONCE_SIZE,
  KEY_CONTEXT_INITIATOR,
  PUBLIC_KEY_SIZE,
  SIGNATURE_SIZE
} from './constants.js'
import {
  deriveKey,
  ensureValidCertificate,
  ensureValidKeyShare,
  signData
} from './utils.js'

const createCertificate = (certificate) => {
  const entrySize = PUBLIC_KEY_SIZE + SIGNATURE_SIZE
  const entries = Math.min(certificate.byteLength / entrySize, 65535)
  return append(
    writeUint16BE(alloc(2), entries),
    certificate.subarray(0, entrySize * entries)
  )
}

const encryptMessage = async (
  secretKey,
  context,
  signature,
  certificate,
  data,
  keyShare
) => {
  const key = await deriveKey(secretKey, context)
  const nonce = alloc(AES_GCM_NONCE_SIZE)
  const message = concat([signature, createCertificate(certificate), data])
  return encrypt(CIPHER_AES256_GCM, key, nonce, message, keyShare)
}

export const authenticate = async (
  signingFunction,
  ourData,
  certificate,
  secretKey,
  ourKeyShare,
  theirKeyShare,
  context = KEY_CONTEXT_INITIATOR
) => {
  const data = createFrom(ourData)
  const [, theirPublicKey] = split(
    await ensureValidKeyShare(theirKeyShare),
    PUBLIC_KEY_SIZE
  )
  const signature = await signData(
    signingFunction,
    concat([data, theirPublicKey])
  )
  return encryptMessage(
    secretKey,
    context,
    signature,
    await ensureValidCertificate(certificate),
    data,
    await ensureValidKeyShare(ourKeyShare)
  )
}

export const identify = (
  signingFunction,
  certificate,
  secretKey,
  ourKeyShare,
  theirKeyShare,
  context
) =>
  authenticate(
    signingFunction,
    createFrom(),
    certificate,
    secretKey,
    ourKeyShare,
    theirKeyShare,
    context
  )
