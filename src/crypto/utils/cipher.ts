import { createFrom, hasSize } from '../../bytes'
import {
  CIPHER_AES128_CBC,
  CIPHER_AES128_CTR,
  CIPHER_AES128_GCM,
  CIPHER_AES128_KEY_SIZE,
  CIPHER_AES192_CBC,
  CIPHER_AES192_CTR,
  CIPHER_AES192_GCM,
  CIPHER_AES192_KEY_SIZE,
  CIPHER_AES256_CBC,
  CIPHER_AES256_CTR,
  CIPHER_AES256_GCM,
  CIPHER_AES256_KEY_SIZE,
  CIPHER_AES_CBC,
  CIPHER_AES_CBC_NONCE_SIZE,
  CIPHER_AES_CTR,
  CIPHER_AES_CTR_COUNTER_BITS,
  CIPHER_AES_CTR_NONCE_SIZE,
  CIPHER_AES_GCM,
  CIPHER_AES_GCM_NONCE_SIZE,
  CIPHER_AES_GCM_TAG_SIZE
} from '../constants'
import { WebCrypto } from '../utils'
import { importSecretKey } from './key-import'

const cipherNames = new Map([
  [CIPHER_AES128_CBC, CIPHER_AES_CBC],
  [CIPHER_AES128_CTR, CIPHER_AES_CTR],
  [CIPHER_AES128_GCM, CIPHER_AES_GCM],
  [CIPHER_AES192_CBC, CIPHER_AES_CBC],
  [CIPHER_AES192_CTR, CIPHER_AES_CTR],
  [CIPHER_AES192_GCM, CIPHER_AES_GCM],
  [CIPHER_AES256_CBC, CIPHER_AES_CBC],
  [CIPHER_AES256_CTR, CIPHER_AES_CTR],
  [CIPHER_AES256_GCM, CIPHER_AES_GCM]
])

const keySizes = new Map([
  [CIPHER_AES128_CBC, CIPHER_AES128_KEY_SIZE],
  [CIPHER_AES128_CTR, CIPHER_AES128_KEY_SIZE],
  [CIPHER_AES128_GCM, CIPHER_AES128_KEY_SIZE],
  [CIPHER_AES192_CBC, CIPHER_AES192_KEY_SIZE],
  [CIPHER_AES192_CTR, CIPHER_AES192_KEY_SIZE],
  [CIPHER_AES192_GCM, CIPHER_AES192_KEY_SIZE],
  [CIPHER_AES256_CBC, CIPHER_AES256_KEY_SIZE],
  [CIPHER_AES256_CTR, CIPHER_AES256_KEY_SIZE],
  [CIPHER_AES256_GCM, CIPHER_AES256_KEY_SIZE]
])

const nonceSizes = new Map([
  [CIPHER_AES128_CBC, CIPHER_AES_CBC_NONCE_SIZE],
  [CIPHER_AES128_CTR, CIPHER_AES_CTR_NONCE_SIZE],
  [CIPHER_AES128_GCM, CIPHER_AES_GCM_NONCE_SIZE],
  [CIPHER_AES192_CBC, CIPHER_AES_CBC_NONCE_SIZE],
  [CIPHER_AES192_CTR, CIPHER_AES_CTR_NONCE_SIZE],
  [CIPHER_AES192_GCM, CIPHER_AES_GCM_NONCE_SIZE],
  [CIPHER_AES256_CBC, CIPHER_AES_CBC_NONCE_SIZE],
  [CIPHER_AES256_CTR, CIPHER_AES_CTR_NONCE_SIZE],
  [CIPHER_AES256_GCM, CIPHER_AES_GCM_NONCE_SIZE]
])

const isSupportedCipher = (cipher: string) => cipherNames.has(cipher)

const getCipherName = (cipher: string) => cipherNames.get(cipher)

export const getKeySize = (cipher: string) => keySizes.get(cipher)

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

export const importCipherKey = async (
  crypto: WebCrypto,
  cipher: string,
  key: BufferSource
) =>
  importSecretKey(
    crypto,
    getCipherName(cipher),
    await ensureValidKey(cipher, key)
  )

export const createCipherParams = async (
  cipher: string,
  nonce: BufferSource,
  associatedData?: BufferSource
): Promise<AesCbcParams | AesCtrParams | AesGcmParams> => {
  const name = getCipherName(await ensureSupportedCipher(cipher))
  const iv = await ensureValidNonce(cipher, nonce)
  if (name === CIPHER_AES_CBC) {
    return { name, iv }
  }
  if (name === CIPHER_AES_CTR) {
    return { name, counter: iv, length: CIPHER_AES_CTR_COUNTER_BITS }
  }
  return {
    name,
    iv,
    additionalData: createFrom(associatedData),
    tagLength: CIPHER_AES_GCM_TAG_SIZE * 8
  }
}

export const getCiphers = () => [...cipherNames.keys()]
