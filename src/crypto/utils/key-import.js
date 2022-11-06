import {
  ALGORITHM_ECDH,
  ALGORITHM_ECDSA,
  ALGORITHM_HKDF,
  ALGORITHM_HMAC,
  ALGORITHM_PBKDF2,
  KEY_FORMAT_PKCS8,
  KEY_FORMAT_RAW,
  KEY_FORMAT_SPKI,
  KEY_USAGE_DERIVE_BITS,
  KEY_USAGE_DERIVE_KEY,
  KEY_USAGE_SIGN,
  KEY_USAGE_VERIFY
} from '../constants'

const getImportFormat = (isPublicKey) =>
  isPublicKey ? KEY_FORMAT_SPKI : KEY_FORMAT_PKCS8

const importKey = (crypto, format, key, algorithm, usages) =>
  crypto.subtle.importKey(format, key, algorithm, false, usages)

const importRawKey = (crypto, key, algorithm, usages) =>
  importKey(crypto, KEY_FORMAT_RAW, key, algorithm, usages)

const importEcdhKey = (crypto, namedCurve, key, isPublicKey) =>
  importKey(
    crypto,
    getImportFormat(isPublicKey),
    key,
    {
      name: ALGORITHM_ECDH,
      namedCurve
    },
    [KEY_USAGE_DERIVE_BITS]
  )

const importSignKey = (crypto, namedCurve, key, isPublicKey) =>
  importKey(
    crypto,
    getImportFormat(isPublicKey),
    key,
    {
      name: ALGORITHM_ECDSA,
      namedCurve
    },
    [isPublicKey ? KEY_USAGE_VERIFY : KEY_USAGE_SIGN]
  )

export const importPrivateKey = (crypto, curve, key) =>
  importEcdhKey(crypto, curve, key, false)

export const importPublicKey = (crypto, curve, key) =>
  importEcdhKey(crypto, curve, key, true)

export const importSignPrivateKey = (crypto, curve, key) =>
  importSignKey(crypto, curve, key, false)

export const importSignPublicKey = (crypto, curve, key) =>
  importSignKey(crypto, curve, key, true)

export const importHkdfKey = (crypto, key) =>
  importRawKey(crypto, key, { name: ALGORITHM_HKDF }, [
    KEY_USAGE_DERIVE_BITS,
    KEY_USAGE_DERIVE_KEY
  ])

export const importHmacKey = (crypto, hash, key) =>
  importRawKey(crypto, key, { name: ALGORITHM_HMAC, hash }, [
    KEY_USAGE_SIGN,
    KEY_USAGE_VERIFY
  ])

export const importPbkdf2Key = (crypto, key) =>
  importRawKey(crypto, key, ALGORITHM_PBKDF2, [
    KEY_USAGE_DERIVE_BITS,
    KEY_USAGE_DERIVE_KEY
  ])
