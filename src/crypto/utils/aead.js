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

const isSupportedCipher = (cipher) => cipherNames.has(cipher)

const getCipherName = (cipher) => cipherNames.get(cipher)

export const getKeySize = (cipher) =>
  keySizes.has(cipher) ? keySizes.get(cipher) : 0

const getNonceSize = (cipher) =>
  nonceSizes.has(cipher) ? nonceSizes.get(cipher) : 0

const getTagSize = (cipher) => (tagSizes.has(cipher) ? tagSizes.get(cipher) : 0)

const importSecretKey = (crypto, cipherName, key) =>
  crypto.subtle.importKey(KEY_FORMAT_RAW, key, cipherName, false, [
    KEY_USAGE_ENCRYPT,
    KEY_USAGE_DECRYPT
  ])

export const ensureSupportedCipher = (cipher) =>
  isSupportedCipher(cipher)
    ? Promise.resolve(cipher)
    : Promise.reject(new Error('Unsupported cipher'))

const ensureValidKey = (cipher, value) => {
  const key = createFrom(value)
  return hasSize(key, getKeySize(cipher))
    ? Promise.resolve(key)
    : Promise.reject(new Error('Invalid key size'))
}

const ensureValidNonce = (cipher, value) => {
  const nonce = createFrom(value)
  return hasSize(nonce, getNonceSize(cipher))
    ? Promise.resolve(nonce)
    : Promise.reject(new Error('Invalid nonce size'))
}

export const createAead =
  (func) =>
  async (crypto, cipher, key, nonce, ...args) => {
    const cipherName = getCipherName(await ensureSupportedCipher(cipher))
    const secretKey = await importSecretKey(
      crypto,
      cipherName,
      await ensureValidKey(cipher, key)
    )
    return createFrom(
      await func(
        crypto,
        cipherName,
        secretKey,
        await ensureValidNonce(cipher, nonce),
        getTagSize(cipher) * 8,
        ...args.map((arg) => createFrom(arg))
      )
    )
  }
