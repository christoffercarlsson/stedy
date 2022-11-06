import { isWebEnvironment, memoizeFirst } from './util'
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
import { getCurves } from './crypto/utils'
import _verify from './crypto/verify'

const crypto = memoizeFirst(async () => {
  /* istanbul ignore next */
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
