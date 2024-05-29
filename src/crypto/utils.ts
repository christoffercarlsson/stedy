import type { webcrypto } from 'crypto'
import {
  createCipherParams,
  ensureSupportedCipher,
  getCiphers,
  getKeySize,
  importCipherKey as importSecretKey
} from './utils/cipher'
import {
  addKeyPrefix,
  ensureSupportedCurve,
  ensureSupportedKey,
  getCurves,
  getHashForCurve,
  identifyCurve,
  removeKeyPrefix
} from './utils/curve'
import exportKeyPair from './utils/export-key-pair'
import { ensureSupportedHash, getHashes, getHashSize } from './utils/hash'
import {
  importHkdfKey,
  importHmacKey,
  importPbkdf2Key,
  importPrivateKey,
  importPublicKey,
  importSignPrivateKey,
  importSignPublicKey
} from './utils/key-import'

export type WebCrypto = Crypto | webcrypto.Crypto

const importCrypto = () => {
  /* istanbul ignore next */
  if (typeof globalThis === 'object' && 'crypto' in globalThis) {
    return Promise.resolve(globalThis.crypto)
  }
  return Promise.reject(new Error('Unable to find crypto'))
}

let crypto: WebCrypto = null

const getCrypto = async () => {
  if (!crypto) {
    crypto = await importCrypto()
  }
  return crypto
}

export {
  addKeyPrefix,
  createCipherParams,
  ensureSupportedCipher,
  ensureSupportedCurve,
  ensureSupportedHash,
  ensureSupportedKey,
  exportKeyPair,
  getCiphers,
  getCrypto,
  getCurves,
  getHashes,
  getHashForCurve,
  getHashSize,
  getKeySize,
  identifyCurve,
  importHkdfKey,
  importHmacKey,
  importPbkdf2Key,
  importPrivateKey,
  importPublicKey,
  importSecretKey,
  importSignPrivateKey,
  importSignPublicKey,
  removeKeyPrefix
}
