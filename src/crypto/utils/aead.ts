import { createFrom, hasSize } from '../../chunk'
import {
  CIPHER_AES128_GCM,
  CIPHER_AES128_GCM_KEY_SIZE,
  CIPHER_AES256_GCM,
  CIPHER_AES256_GCM_KEY_SIZE,
  CIPHER_AES_GCM,
  CIPHER_AES_GCM_NONCE_SIZE,
  CIPHER_AES_GCM_TAG_SIZE,
  KEY_FORMAT_RAW,
  KEY_USAGE_DECRYPT,
  KEY_USAGE_ENCRYPT
} from '../constants'
import { WebCrypto } from '../utils'

const cipherNames = new Map([
  [CIPHER_AES128_GCM, CIPHER_AES_GCM],
  [CIPHER_AES256_GCM, CIPHER_AES_GCM]
])

const keySizes = new Map([
  [CIPHER_AES128_GCM, CIPHER_AES128_GCM_KEY_SIZE],
  [CIPHER_AES256_GCM, CIPHER_AES256_GCM_KEY_SIZE]
])

const nonceSizes = new Map([
  [CIPHER_AES128_GCM, CIPHER_AES_GCM_NONCE_SIZE],
  [CIPHER_AES256_GCM, CIPHER_AES_GCM_NONCE_SIZE]
])

const tagSizes = new Map([
  [CIPHER_AES128_GCM, CIPHER_AES_GCM_TAG_SIZE],
  [CIPHER_AES256_GCM, CIPHER_AES_GCM_TAG_SIZE]
])

const isSupportedCipher = (cipher: string) => cipherNames.has(cipher)

const getCipherName = (cipher: string) => cipherNames.get(cipher)

export const getKeySize = (cipher: string) => keySizes.get(cipher)

const importSecretKey = (
  crypto: WebCrypto,
  cipherName: string,
  key: BufferSource
) =>
  crypto.subtle.importKey(KEY_FORMAT_RAW, key, cipherName, false, [
    KEY_USAGE_ENCRYPT,
    KEY_USAGE_DECRYPT
  ])

export const ensureSupportedCipher = (cipher: string) =>
  isSupportedCipher(cipher)
    ? Promise.resolve(cipher)
    : Promise.reject(new Error('Unsupported cipher'))

const ensureValidKey = (cipher: string, value: BufferSource) => {
  const key = createFrom(value)
  return hasSize(key, keySizes.get(cipher))
    ? Promise.resolve(key)
    : Promise.reject(new Error('Invalid key size'))
}

const ensureValidNonce = (cipher: string, value: BufferSource) => {
  const nonce = createFrom(value)
  return hasSize(nonce, nonceSizes.get(cipher))
    ? Promise.resolve(nonce)
    : Promise.reject(new Error('Invalid nonce size'))
}

export const createAead = async (
  crypto: WebCrypto,
  cipher: string,
  key: BufferSource,
  nonce: BufferSource
) => {
  const name = getCipherName(await ensureSupportedCipher(cipher))
  const iv = await ensureValidNonce(cipher, nonce)
  const secretKey = await importSecretKey(
    crypto,
    name,
    await ensureValidKey(cipher, key)
  )
  const tagLength = tagSizes.get(cipher) * 8
  return { name, iv, secretKey, tagLength }
}
