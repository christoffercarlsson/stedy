import { concat, startsWith } from '../../chunk.js'
import {
  ALGORITHM_ECDH,
  ALGORITHM_ECDSA,
  ALGORITHM_EDDSA,
  CURVE_CURVE25519,
  CURVE_P256,
  CURVE_P384,
  CURVE_P521
} from '../constants.js'

const curves = [CURVE_P256, CURVE_P384, CURVE_P521, CURVE_CURVE25519]

const prefixes = [
  [
    // P-256 private key
    CURVE_P256,
    [ALGORITHM_ECDH, ALGORITHM_ECDSA],
    false,
    Uint8Array.from([
      48, 129, 135, 2, 1, 0, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42,
      134, 72, 206, 61, 3, 1, 7, 4, 109, 48, 107, 2, 1, 1, 4, 32
    ])
  ],
  [
    // P-384 private key
    CURVE_P384,
    [ALGORITHM_ECDH, ALGORITHM_ECDSA],
    false,
    Uint8Array.from([
      48, 129, 182, 2, 1, 0, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43,
      129, 4, 0, 34, 4, 129, 158, 48, 129, 155, 2, 1, 1, 4, 48
    ])
  ],
  [
    // P-521 private key
    CURVE_P521,
    [ALGORITHM_ECDH, ALGORITHM_ECDSA],
    false,
    Uint8Array.from([
      48, 129, 238, 2, 1, 0, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43,
      129, 4, 0, 35, 4, 129, 214, 48, 129, 211, 2, 1, 1, 4, 66
    ])
  ],
  [
    // P-256 public key
    CURVE_P256,
    [ALGORITHM_ECDH, ALGORITHM_ECDSA],
    true,
    Uint8Array.from([
      48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206,
      61, 3, 1, 7, 3, 66, 0, 4
    ])
  ],
  [
    // P-384 public key
    CURVE_P384,
    [ALGORITHM_ECDH, ALGORITHM_ECDSA],
    true,
    Uint8Array.from([
      48, 118, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0,
      34, 3, 98, 0, 4
    ])
  ],
  [
    // P-521 public key
    CURVE_P521,
    [ALGORITHM_ECDH, ALGORITHM_ECDSA],
    true,
    Uint8Array.from([
      48, 129, 155, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4,
      0, 35, 3, 129, 134, 0, 4
    ])
  ],
  // X25519 private key
  [
    CURVE_CURVE25519,
    [ALGORITHM_ECDH],
    false,
    Uint8Array.from([48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32])
  ],
  // Ed25519 private key
  [
    CURVE_CURVE25519,
    [ALGORITHM_EDDSA],
    false,
    Uint8Array.from([48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32])
  ],
  // X25519 public key
  [
    CURVE_CURVE25519,
    [ALGORITHM_ECDH],
    true,
    Uint8Array.from([48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0])
  ],
  // Ed25519 public key
  [
    CURVE_CURVE25519,
    [ALGORITHM_EDDSA],
    true,
    Uint8Array.from([48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0])
  ]
]

const findPrefix = (key) =>
  prefixes.find(([, , , prefix]) => startsWith(key, prefix)) || []

const getAlgorithm = (curve, isSigningKey) => {
  if (isSigningKey) {
    return curve === CURVE_CURVE25519 ? ALGORITHM_EDDSA : ALGORITHM_ECDSA
  }
  return ALGORITHM_ECDH
}

export const addKeyPrefix = (curve, isSigningKey, isPublicKey, key) => {
  const algorithm = getAlgorithm(curve, isSigningKey)
  const [, , , prefix] =
    prefixes.find(
      ([c, algorithms, isPublic]) =>
        c === curve &&
        algorithms.includes(algorithm) &&
        isPublic === isPublicKey
    ) || []
  return concat([prefix || Uint8Array.from([]), key])
}

export const removeKeyPrefix = (key) => {
  const [, , , prefix] = findPrefix(key)
  if (prefix) {
    return key.subarray(prefix.byteLength)
  }
  return Uint8Array.from([])
}

const identifyCurve = (key) => {
  const [curve] = findPrefix(key)
  return curve || ''
}

export const getCurves = () => curves

const isSupportedCurve = (curve) => getCurves().includes(curve)

export const ensureSupportedCurve = (curve) =>
  isSupportedCurve(curve)
    ? Promise.resolve(curve)
    : Promise.reject(new Error('Unsupported elliptic curve'))

export const ensureSupportedKey = (key) =>
  ensureSupportedCurve(identifyCurve(key))
