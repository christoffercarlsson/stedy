import {
  ALGORITHM_ECDH,
  ALGORITHM_ECDSA,
  ALGORITHM_HKDF,
  ALGORITHM_HMAC,
  ALGORITHM_PBKDF2,
  KEY_FORMAT_PKCS8,
  KEY_FORMAT_RAW,
  KEY_FORMAT_SPKI,
  KEY_USAGE_DECRYPT,
  KEY_USAGE_DERIVE_BITS,
  KEY_USAGE_DERIVE_KEY,
  KEY_USAGE_ENCRYPT,
  KEY_USAGE_SIGN,
  KEY_USAGE_VERIFY
} from '../constants'
import { WebCrypto } from '../utils'

const getImportFormat = (isPublicKey: boolean) =>
  isPublicKey ? KEY_FORMAT_SPKI : KEY_FORMAT_PKCS8

const importKey = (
  crypto: WebCrypto,
  format: 'pkcs8' | 'spki' | 'raw',
  key: BufferSource,
  algorithm: AlgorithmIdentifier,
  usages: KeyUsage[]
) => crypto.subtle.importKey(format, key, algorithm, false, usages)

const importRawKey = (
  crypto: WebCrypto,
  key: BufferSource,
  algorithm: AlgorithmIdentifier,
  usages: KeyUsage[]
) => importKey(crypto, KEY_FORMAT_RAW, key, algorithm, usages)

const importEcdhKey = (
  crypto: WebCrypto,
  namedCurve: string,
  key: BufferSource,
  isPublicKey: boolean
) =>
  importKey(
    crypto,
    getImportFormat(isPublicKey),
    key,
    {
      name: ALGORITHM_ECDH,
      namedCurve
    } as AlgorithmIdentifier,
    [KEY_USAGE_DERIVE_BITS]
  )

export const importSecretKey = (
  crypto: WebCrypto,
  algorithm: string,
  key: BufferSource
) =>
  importRawKey(crypto, key, algorithm, [KEY_USAGE_ENCRYPT, KEY_USAGE_DECRYPT])

const importSignKey = (
  crypto: WebCrypto,
  namedCurve: string,
  key: BufferSource,
  isPublicKey: boolean
) =>
  importKey(
    crypto,
    getImportFormat(isPublicKey),
    key,
    {
      name: ALGORITHM_ECDSA,
      namedCurve
    } as AlgorithmIdentifier,
    [isPublicKey ? KEY_USAGE_VERIFY : KEY_USAGE_SIGN]
  )

export const importPrivateKey = (
  crypto: WebCrypto,
  curve: string,
  key: BufferSource
) => importEcdhKey(crypto, curve, key, false)

export const importPublicKey = (
  crypto: WebCrypto,
  curve: string,
  key: BufferSource
) => importEcdhKey(crypto, curve, key, true)

export const importSignPrivateKey = (
  crypto: WebCrypto,
  curve: string,
  key: BufferSource
) => importSignKey(crypto, curve, key, false)

export const importSignPublicKey = (
  crypto: WebCrypto,
  curve: string,
  key: BufferSource
) => importSignKey(crypto, curve, key, true)

export const importHkdfKey = (crypto: WebCrypto, key: BufferSource) =>
  importRawKey(crypto, key, { name: ALGORITHM_HKDF }, [
    KEY_USAGE_DERIVE_BITS,
    KEY_USAGE_DERIVE_KEY
  ])

export const importHmacKey = (
  crypto: WebCrypto,
  hash: string,
  key: BufferSource
) =>
  importRawKey(
    crypto,
    key,
    { name: ALGORITHM_HMAC, hash } as AlgorithmIdentifier,
    [KEY_USAGE_SIGN, KEY_USAGE_VERIFY]
  )

export const importPbkdf2Key = (crypto: WebCrypto, key: BufferSource) =>
  importRawKey(crypto, key, ALGORITHM_PBKDF2, [
    KEY_USAGE_DERIVE_BITS,
    KEY_USAGE_DERIVE_KEY
  ])
