import {
  CIPHER_AES256_GCM,
  CURVE_CURVE25519,
  HASH_SHA512
} from './crypto/constants'
import createCipher, {
  CipherFunctions,
  DecryptFunction,
  EncryptFunction,
  GenerateKeyFunction
} from './crypto/create-cipher'
import createCurve, {
  CurveFunctions,
  DiffieHellmanFunction,
  KeyPairFunction,
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
import _randomBytes from './crypto/random-bytes'
import { getCiphers, getCrypto, getCurves, getHashes } from './crypto/utils'

const { decrypt, encrypt, generateKey } = createCipher(CIPHER_AES256_GCM)
const { diffieHellman, keyPair, signKeyPair, importKey, sign, verify } =
  createCurve(CURVE_CURVE25519)
const { hash, hkdf, hmac, pbkdf2 } = createHash(HASH_SHA512)

const randomBytes = async (size: number) =>
  _randomBytes(await getCrypto(), size)

export {
  CipherFunctions,
  CurveFunctions,
  DecryptFunction,
  DiffieHellmanFunction,
  EncryptFunction,
  GenerateKeyFunction,
  KeyPairFunction,
  HashFunctions,
  HashFunction,
  HKDFFunction,
  HMACFunction,
  ImportKeyFunction,
  PBKDF2Function,
  SignFunction,
  VerifyFunction,
  createCipher,
  createCurve,
  createHash,
  decrypt,
  diffieHellman,
  encrypt,
  exportKey,
  generateKey,
  getCiphers,
  getCurves,
  getHashes,
  hash,
  hkdf,
  hmac,
  importKey,
  keyPair,
  pbkdf2,
  randomBytes,
  sign,
  signKeyPair,
  verify
}
