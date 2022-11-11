import type { webcrypto } from 'crypto'
import { isWebEnvironment, memoizeFirst } from '../util'
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

const getCrypto = memoizeFirst(async () => {
  /* istanbul ignore next */
  if (isWebEnvironment()) {
    return window.crypto
  }
  // eslint-disable-next-line node/no-unsupported-features/es-syntax
  const { webcrypto } = await import('crypto')
  return webcrypto
}) as () => Promise<WebCrypto>

export {
  addKeyPrefix,
  createAead,
  ensureSupportedCipher,
  ensureSupportedCurve,
  ensureSupportedHash,
  ensureSupportedKey,
  exportKeyPair,
  getCrypto,
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
