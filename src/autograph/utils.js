import { alloc, createFrom, hasSize } from '../chunk.js'
import {
  CURVE_CURVE25519,
  exportKey,
  HASH_SHA512,
  hkdf,
  importKey as importRawKey,
  verify
} from '../crypto.js'
import {
  AES_GCM_KEY_SIZE,
  HKDF_OUTPUT_SIZE,
  HKDF_SALT_SIZE,
  KEY_CONTEXT_AGREEMENT,
  KEY_CONTEXT_INITIATOR,
  KEY_CONTEXT_RESPONDER,
  PRIVATE_KEY_SIZE,
  PUBLIC_KEY_SIZE,
  SIGNATURE_SIZE
} from './constants.js'

export const decodeKeyPair = ({ publicKey, privateKey }, encoding) => ({
  publicKey: createFrom(publicKey, encoding),
  privateKey: createFrom(privateKey, encoding)
})

const ensureView = (value, size, message) => {
  const view = createFrom(value)
  if (!hasSize(view, size)) {
    return Promise.reject(new Error(message))
  }
  return Promise.resolve(view)
}

const ensureViewEntries = (value, size, message) => {
  const view = createFrom(value)
  if (view.byteLength % size !== 0) {
    return Promise.reject(new Error(message))
  }
  return Promise.resolve(view)
}

export const ensureValidCertificate = (
  certificate,
  message = 'Invalid certificate size'
) => ensureViewEntries(certificate, PUBLIC_KEY_SIZE + SIGNATURE_SIZE, message)

export const ensureValidPrivateKey = (
  key,
  message = 'Invalid private key size'
) => ensureView(key, PRIVATE_KEY_SIZE, message)

export const ensureValidPublicKey = (
  key,
  message = 'Invalid public key size'
) => ensureView(key, PUBLIC_KEY_SIZE, message)

export const ensureValidKeyContext = async (
  context,
  message = 'Invalid key context'
) => {
  const view = await ensureView(
    createFrom(Number.isInteger(context) ? [context] : context),
    1,
    message
  )
  if (
    !(
      view[0] in
      [KEY_CONTEXT_INITIATOR, KEY_CONTEXT_RESPONDER, KEY_CONTEXT_AGREEMENT]
    )
  ) {
    return Promise.reject(new Error(message))
  }
  return Promise.resolve(view)
}

export const ensureValidKeyShare = (
  keyShare,
  message = 'Invalid key share size'
) => ensureView(keyShare, PUBLIC_KEY_SIZE * 2, message)

export const ensureValidSecretKey = (
  key,
  message = 'Invalid secret key size'
) => ensureView(key, AES_GCM_KEY_SIZE, message)

export const ensureValidSignature = (
  signature,
  message = 'Invalid signature size'
) => ensureView(signature, SIGNATURE_SIZE, message)

export const ensureValidTrustedParties = (
  trustedParties,
  message = 'Invalid trusted parties size'
) => ensureViewEntries(trustedParties, PUBLIC_KEY_SIZE, message)

export const ensureValidTrustThreshold = (
  threshold,
  message = 'Invalid trust threshold'
) => {
  if (!(Number.isInteger(threshold) && threshold >= 0)) {
    return Promise.reject(new Error(message))
  }
  return Promise.resolve(Math.min(threshold, 65535))
}

export const exportKeyPair = async ({ publicKey, privateKey }) => ({
  publicKey: await exportKey(publicKey),
  privateKey: await exportKey(privateKey)
})

const importKey = async (key, isSigningKey, isPublicKey) =>
  importRawKey(
    CURVE_CURVE25519,
    isSigningKey,
    isPublicKey,
    isPublicKey
      ? await ensureValidPublicKey(key)
      : await ensureValidPrivateKey(key)
  )

export const importPrivateKey = (key) => importKey(key, false, false)

export const importPrivateSigningKey = (key) => importKey(key, true, false)

export const importPublicKey = (key) => importKey(key, false, true)

export const importPublicSigningKey = (key) => importKey(key, true, true)

export const deriveKey = async (key, context) => {
  const salt = alloc(HKDF_SALT_SIZE)
  return hkdf(
    HASH_SHA512,
    await ensureValidSecretKey(key),
    salt,
    await ensureValidKeyContext(context),
    HKDF_OUTPUT_SIZE
  )
}

export const signData = async (sign, data) => {
  const signature = await sign(createFrom(data))
  return ensureValidSignature(
    signature,
    'Invalid signature from signing function'
  )
}

export const verifyData = async (data, publicKey, signature) =>
  verify(
    createFrom(data),
    await importPublicSigningKey(publicKey),
    await ensureValidSignature(signature)
  )
