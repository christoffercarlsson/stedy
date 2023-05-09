import type { Cipher, Decipher } from 'crypto'
import { createFrom } from '../../bytes'
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
  CIPHER_AES_GCM_TAG_SIZE,
  CIPHER_CHACHA20_POLY1305,
  CIPHER_CHACHA20_POLY1305_KEY_SIZE,
  CIPHER_CHACHA20_POLY1305_NAME,
  CIPHER_CHACHA20_POLY1305_NONCE_SIZE
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
  [CIPHER_AES256_GCM, CIPHER_AES_GCM],
  [CIPHER_CHACHA20_POLY1305, CIPHER_CHACHA20_POLY1305_NAME]
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
  [CIPHER_AES256_GCM, CIPHER_AES256_KEY_SIZE],
  [CIPHER_CHACHA20_POLY1305, CIPHER_CHACHA20_POLY1305_KEY_SIZE]
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
  [CIPHER_AES256_GCM, CIPHER_AES_GCM_NONCE_SIZE],
  [CIPHER_CHACHA20_POLY1305, CIPHER_CHACHA20_POLY1305_NONCE_SIZE]
])

export const getCiphers = () => {
  const isWebEnv = typeof window === 'object'
  return [...cipherNames.keys()].filter(
    (cipher) => !(isWebEnv && cipher === CIPHER_CHACHA20_POLY1305)
  )
}

const isSupportedCipher = (cipher: string) => getCiphers().includes(cipher)

const getCipherName = (cipher: string) => cipherNames.get(cipher)

export const getKeySize = (cipher: string) => keySizes.get(cipher)

export const getNonceSize = (cipher: string) => nonceSizes.get(cipher)

export const ensureSupportedCipher = (cipher: string) =>
  isSupportedCipher(cipher)
    ? Promise.resolve(cipher)
    : Promise.reject(new Error('Unsupported cipher'))

const ensureValidCipherParams = async (
  cipher: string,
  key?: BufferSource,
  nonce?: BufferSource
) => ({
  name: getCipherName(await ensureSupportedCipher(cipher)),
  key: await ensureValidKey(cipher, key),
  nonce: await ensureValidNonce(cipher, nonce)
})

const ensureValidKey = (cipher: string, value: BufferSource) => {
  const key = createFrom(value)
  return key.hasSize(keySizes.get(cipher))
    ? Promise.resolve(key)
    : Promise.reject(new Error('Invalid key size'))
}

export const ensureValidNonce = (cipher: string, value: BufferSource) => {
  const nonce = createFrom(value)
  return nonce.hasSize(nonceSizes.get(cipher))
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

export const createNodeCipher = async (
  cipherName: string,
  key: BufferSource,
  nonce: BufferSource,
  associatedData?: BufferSource
) => {
  const params = await ensureValidCipherParams(cipherName, key, nonce)
  const { createCipheriv } = await import('crypto')
  const cipher = createCipheriv(params.name, params.key, params.nonce)
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  // eslint-disable-next-line @typescript-eslint/no-unsafe-call
  return cipher.setAAD(createFrom(associatedData)) as Cipher
}

export const createNodeDecipher = async (
  cipherName: string,
  key: BufferSource,
  nonce: BufferSource,
  associatedData?: BufferSource
) => {
  const params = await ensureValidCipherParams(cipherName, key, nonce)
  const { createDecipheriv } = await import('crypto')
  const decipher = createDecipheriv(params.name, params.key, params.nonce)
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  // eslint-disable-next-line @typescript-eslint/no-unsafe-call
  return decipher.setAAD(createFrom(associatedData)) as Decipher
}
