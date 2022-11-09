import type { webcrypto } from 'crypto'
import { createAead, ensureSupportedCipher, getKeySize } from './utils/aead'
import {
  addKeyPrefix,
  ensureSupportedCurve,
  ensureSupportedKey,
  getCurves,
  identifyCurve,
  removeKeyPrefix
} from './utils/curve'
import exportKeyPair from './utils/export-key-pair'
import { ensureSupportedHash, getHashSize } from './utils/hash'
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

export {
  addKeyPrefix,
  createAead,
  ensureSupportedCipher,
  ensureSupportedCurve,
  ensureSupportedHash,
  ensureSupportedKey,
  exportKeyPair,
  getCurves,
  getHashSize,
  getKeySize,
  identifyCurve,
  importHkdfKey,
  importHmacKey,
  importPbkdf2Key,
  importPrivateKey,
  importPublicKey,
  importSignPrivateKey,
  importSignPublicKey,
  removeKeyPrefix
}
