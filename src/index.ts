import {
  CIPHER_AES256_GCM,
  CURVE_CURVE25519,
  HASH_SHA512
} from './crypto/constants'
import createCipher, {
  CipherFunctions,
  DecryptFunction,
  EncryptFunction,
  GenerateKeyFunction,
  GenerateNonceFunction
} from './crypto/create-cipher'
import createCurve, {
  CurveFunctions,
  DiffieHellmanFunction,
  GenerateKeyPairFunction,
  ImportKeyFunction,
  SignFunction,
  VerifyFunction
} from './crypto/create-curve'
import createHash, {
  HashFunctions,
  HashFunction,
  HKDFFunction,
  HMACFunction,
  PBKDF2Function
} from './crypto/create-hash'
import exportKey from './crypto/export-key'
import _generateRandomBytes from './crypto/generate-random-bytes'
import { getCiphers, getCrypto, getCurves, getHashes } from './crypto/utils'
import {
  ENCODING_BASE32,
  ENCODING_BASE64,
  ENCODING_BASE64_UNPADDED,
  ENCODING_BASE64_URL,
  ENCODING_BASE64_URL_UNPADDED,
  ENCODING_HEX,
  ENCODING_JSON,
  ENCODING_PEM,
  ENCODING_UTF8,
  alloc,
  concat,
  Bytes,
  createFrom,
  fromInteger,
  fromString
} from './bytes'

const { decrypt, encrypt, generateKey, generateNonce } =
  createCipher(CIPHER_AES256_GCM)
const {
  diffieHellman,
  generateKeyPair,
  generateSignKeyPair,
  importKey,
  sign,
  verify
} = createCurve(CURVE_CURVE25519)
const { hash, hkdf, hmac, pbkdf2 } = createHash(HASH_SHA512)

const generateRandomBytes = async (size: number) =>
  _generateRandomBytes(await getCrypto(), size)

export type {
  CipherFunctions,
  CurveFunctions,
  DecryptFunction,
  DiffieHellmanFunction,
  EncryptFunction,
  GenerateKeyFunction,
  GenerateKeyPairFunction,
  GenerateNonceFunction,
  HashFunctions,
  HashFunction,
  HKDFFunction,
  HMACFunction,
  ImportKeyFunction,
  PBKDF2Function,
  SignFunction,
  VerifyFunction
}

export {
  ENCODING_BASE32,
  ENCODING_BASE64,
  ENCODING_BASE64_UNPADDED,
  ENCODING_BASE64_URL,
  ENCODING_BASE64_URL_UNPADDED,
  ENCODING_HEX,
  ENCODING_JSON,
  ENCODING_PEM,
  ENCODING_UTF8,
  alloc,
  concat,
  Bytes,
  createCipher,
  createCurve,
  createFrom,
  createHash,
  decrypt,
  diffieHellman,
  encrypt,
  exportKey,
  fromInteger,
  fromString,
  generateKey,
  generateKeyPair,
  generateNonce,
  generateRandomBytes,
  generateSignKeyPair,
  getCiphers,
  getCurves,
  getHashes,
  hash,
  hkdf,
  hmac,
  importKey,
  pbkdf2,
  sign,
  verify
}
