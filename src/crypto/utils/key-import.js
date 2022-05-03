import {
  ALGORITHM_ECDH,
  ALGORITHM_ECDSA,
  ALGORITHM_HKDF,
  ALGORITHM_HMAC,
  ALGORITHM_NODE_ED448,
  ALGORITHM_PBKDF2,
  CURVE_CURVE448,
  CURVE_NODE_ED448,
  CURVE_NODE_X448,
  KEY_FORMAT_PKCS8,
  KEY_FORMAT_RAW,
  KEY_FORMAT_SPKI,
  KEY_SIZE_NODE_ED448,
  KEY_SIZE_NODE_X448,
  KEY_USAGE_DERIVE_BITS,
  KEY_USAGE_DERIVE_KEY,
  KEY_USAGE_SIGN,
  KEY_USAGE_VERIFY
} from '../constants.js'

const getEcdhAlgorithm = (curve, isPublicKey) => {
  const params = {
    name: ALGORITHM_ECDH,
    namedCurve: curve === CURVE_CURVE448 ? CURVE_NODE_X448 : curve
  }
  if (curve === CURVE_CURVE448) {
    return { ...params, public: isPublicKey }
  }
  return params
}

const getSignAlgorithm = (curve, isPublicKey) => {
  if (curve === CURVE_CURVE448) {
    return {
      name: ALGORITHM_NODE_ED448,
      namedCurve: CURVE_NODE_ED448,
      public: isPublicKey
    }
  }
  return {
    name: ALGORITHM_ECDSA,
    namedCurve: curve
  }
}

const getImportFormat = (curve, isPublicKey) => {
  if (curve === CURVE_CURVE448) {
    return KEY_FORMAT_RAW
  }
  return isPublicKey ? KEY_FORMAT_SPKI : KEY_FORMAT_PKCS8
}

const getImportKey = (curve, key, sign) =>
  curve === CURVE_CURVE448
    ? key.subarray(
        key.byteLength - (sign ? KEY_SIZE_NODE_ED448 : KEY_SIZE_NODE_X448)
      )
    : key

const getEcdhImportKey = (curve, key) => getImportKey(curve, key, false)

const getSignImportKey = (curve, key) => getImportKey(curve, key, true)

const importKey = (crypto, format, key, algorithm, usages) =>
  crypto.subtle.importKey(format, key, algorithm, false, usages)

const importRawKey = (crypto, key, algorithm, usages) =>
  importKey(crypto, KEY_FORMAT_RAW, key, algorithm, usages)

const importEcdhKey = (crypto, curve, key, isPublicKey) =>
  importKey(
    crypto,
    getImportFormat(curve, isPublicKey),
    getEcdhImportKey(curve, key),
    getEcdhAlgorithm(curve, isPublicKey),
    [KEY_USAGE_DERIVE_BITS]
  )

const importSignKey = (crypto, curve, key, isPublicKey) =>
  importKey(
    crypto,
    getImportFormat(curve, isPublicKey),
    getSignImportKey(curve, key),
    getSignAlgorithm(curve, isPublicKey),
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
