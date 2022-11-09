import { isWebEnvironment } from './util'
import {
  CIPHER_AES128_GCM,
  CIPHER_AES256_GCM,
  CURVE_CURVE25519,
  CURVE_P256,
  CURVE_P384,
  CURVE_P521,
  HASH_SHA256,
  HASH_SHA384,
  HASH_SHA512
} from './crypto/constants'
import _decrypt from './crypto/decrypt'
import _deriveSharedSecret from './crypto/derive-shared-secret'
import _encrypt from './crypto/encrypt'
import exportKey from './crypto/export-key'
import _generateKeyPair from './crypto/generate-key-pair'
import _generateKey from './crypto/generate-key'
import _generateRandomBytes from './crypto/generate-random-bytes'
import _generateSignKeyPair from './crypto/generate-sign-key-pair'
import _hash from './crypto/hash'
import _hkdf from './crypto/hkdf'
import _hmac from './crypto/hmac'
import importKey from './crypto/import-key'
import _pbkdf2 from './crypto/pbkdf2'
import _sign from './crypto/sign'
import { getCurves, WebCrypto } from './crypto/utils'
import _verify from './crypto/verify'

let crypto: WebCrypto = null

const importCrypto = async () => {
  /* istanbul ignore next */
  if (isWebEnvironment()) {
    return window.crypto
  }
  // eslint-disable-next-line node/no-unsupported-features/es-syntax
  const { webcrypto } = await import('crypto')
  return webcrypto
}

const getCrypto = async () => {
  if (!crypto) {
    crypto = await importCrypto()
  }
  return crypto
}

const decrypt = async (
  cipher: string,
  key: BufferSource,
  nonce: BufferSource,
  ciphertext: BufferSource,
  associatedData?: BufferSource
) => _decrypt(await getCrypto(), cipher, key, nonce, ciphertext, associatedData)

const deriveSharedSecret = async (
  ourPrivateKey: BufferSource,
  theirPublicKey: BufferSource,
  size?: number
) => _deriveSharedSecret(await getCrypto(), ourPrivateKey, theirPublicKey, size)

const encrypt = async (
  cipher: string,
  key: BufferSource,
  nonce: BufferSource,
  message: BufferSource,
  associatedData?: BufferSource
) => _encrypt(await getCrypto(), cipher, key, nonce, message, associatedData)

const generateKeyPair = async (curve: string) =>
  _generateKeyPair(await getCrypto(), curve)

const generateKey = async (curve: string) =>
  _generateKey(await getCrypto(), curve)

const generateRandomBytes = async (size: number) =>
  _generateRandomBytes(await getCrypto(), size)

const generateSignKeyPair = async (curve: string) =>
  _generateSignKeyPair(await getCrypto(), curve)

const hash = async (
  algorithm: string,
  message: BufferSource,
  iterations?: number
) => _hash(await getCrypto(), algorithm, message, iterations)

const hkdf = async (
  algorithm: string,
  message: BufferSource,
  salt: BufferSource,
  info?: BufferSource,
  size?: number
) => _hkdf(await getCrypto(), algorithm, message, salt, info, size)

const hmac = async (
  algorithm: string,
  key: BufferSource,
  message: BufferSource
) => _hmac(await getCrypto(), algorithm, key, message)

const pbkdf2 = async (
  hash: string,
  password: BufferSource,
  salt: BufferSource,
  iterations?: number,
  size?: number
) => _pbkdf2(await getCrypto(), hash, password, salt, iterations, size)

const sign = async (
  message: BufferSource,
  privateKey: BufferSource,
  hash?: string
) => _sign(await getCrypto(), message, privateKey, hash)

const verify = async (
  message: BufferSource,
  publicKey: BufferSource,
  signature: BufferSource,
  hash?: string
) => _verify(await getCrypto(), message, publicKey, signature, hash)

export {
  CIPHER_AES128_GCM,
  CIPHER_AES256_GCM,
  CURVE_CURVE25519,
  CURVE_P256,
  CURVE_P384,
  CURVE_P521,
  HASH_SHA256,
  HASH_SHA384,
  HASH_SHA512,
  decrypt,
  deriveSharedSecret,
  encrypt,
  exportKey,
  generateKeyPair,
  generateKey,
  generateRandomBytes,
  generateSignKeyPair,
  getCurves,
  hash,
  hkdf,
  hmac,
  importKey,
  pbkdf2,
  sign,
  verify
}
