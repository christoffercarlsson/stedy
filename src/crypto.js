import { memoizeFirst } from './util.js'
import {
  CIPHER_AES128_GCM,
  CIPHER_AES256_GCM,
  CURVE_CURVE448,
  CURVE_CURVE25519,
  CURVE_P256,
  CURVE_P384,
  CURVE_P521,
  HASH_SHA256,
  HASH_SHA384,
  HASH_SHA512
} from './crypto/constants.js'
import _decrypt from './crypto/decrypt.js'
import _deriveSharedSecret from './crypto/derive-shared-secret.js'
import _encrypt from './crypto/encrypt.js'
import exportKey from './crypto/export-key.js'
import _generateKeyPair from './crypto/generate-key-pair.js'
import _generateKey from './crypto/generate-key.js'
import _generateRandomBytes from './crypto/generate-random-bytes.js'
import _generateSignKeyPair from './crypto/generate-sign-key-pair.js'
import _hash from './crypto/hash.js'
import _hkdf from './crypto/hkdf.js'
import _hmac from './crypto/hmac.js'
import importKey from './crypto/import-key.js'
import _pbkdf2 from './crypto/pbkdf2.js'
import _sign from './crypto/sign.js'
import { isWebEnvironment } from './crypto/utils.js'
import _verify from './crypto/verify.js'

const crypto = memoizeFirst(async () => {
  if (isWebEnvironment()) {
    return window.crypto
  }
  const { webcrypto } = await import('crypto')
  return webcrypto
})

const createFn =
  (fn) =>
  async (...args) =>
    fn(await crypto(), ...args)

const decrypt = createFn(_decrypt)
const deriveSharedSecret = createFn(_deriveSharedSecret)
const encrypt = createFn(_encrypt)
const generateKeyPair = createFn(_generateKeyPair)
const generateKey = createFn(_generateKey)
const generateRandomBytes = createFn(_generateRandomBytes)
const generateSignKeyPair = createFn(_generateSignKeyPair)
const hash = createFn(_hash)
const hkdf = createFn(_hkdf)
const hmac = createFn(_hmac)
const pbkdf2 = createFn(_pbkdf2)
const sign = createFn(_sign)
const verify = createFn(_verify)

export {
  CIPHER_AES128_GCM,
  CIPHER_AES256_GCM,
  CURVE_CURVE448,
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
  hash,
  hkdf,
  hmac,
  importKey,
  pbkdf2,
  sign,
  verify
}
