import type { webcrypto } from 'crypto'
import {
  createCipherParams,
  createNodeCipher,
  createNodeDecipher,
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

const importCrypto = async () => {
  /* istanbul ignore next */
  if (typeof window === 'object') {
    return window.crypto
  }
  // eslint-disable-next-line node/no-unsupported-features/es-syntax
  const { webcrypto } = await import('crypto')
  return webcrypto
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
  createNodeCipher,
  createNodeDecipher,
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
