import { concat, createFrom, Chunk } from '../../bytes'
import {
  ALGORITHM_ECDH,
  ALGORITHM_ECDSA,
  ALGORITHM_EDDSA,
  CURVE_CURVE25519,
  CURVE_P256,
  CURVE_P384,
  CURVE_P521,
  HASH_SHA256,
  HASH_SHA384,
  HASH_SHA512
} from '../constants'

type KeyPrefix = {
  curve: string
  algorithms: string[]
  isPublic: boolean
  prefix: Uint8Array
}

const curveHashes = new Map([
  [CURVE_P256, HASH_SHA256],
  [CURVE_P384, HASH_SHA384],
  [CURVE_P521, HASH_SHA512]
])

const curves = [CURVE_P256, CURVE_P384, CURVE_P521, CURVE_CURVE25519]

const prefixes: KeyPrefix[] = [
  {
    // P-256 private key
    curve: CURVE_P256,
    algorithms: [ALGORITHM_ECDH, ALGORITHM_ECDSA],
    isPublic: false,
    prefix: Chunk.from([
      48, 129, 135, 2, 1, 0, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42,
      134, 72, 206, 61, 3, 1, 7, 4, 109, 48, 107, 2, 1, 1, 4, 32
    ])
  },
  {
    // P-384 private key
    curve: CURVE_P384,
    algorithms: [ALGORITHM_ECDH, ALGORITHM_ECDSA],
    isPublic: false,
    prefix: Chunk.from([
      48, 129, 182, 2, 1, 0, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43,
      129, 4, 0, 34, 4, 129, 158, 48, 129, 155, 2, 1, 1, 4, 48
    ])
  },
  {
    // P-521 private key
    curve: CURVE_P521,
    algorithms: [ALGORITHM_ECDH, ALGORITHM_ECDSA],
    isPublic: false,
    prefix: Chunk.from([
      48, 129, 238, 2, 1, 0, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43,
      129, 4, 0, 35, 4, 129, 214, 48, 129, 211, 2, 1, 1, 4, 66
    ])
  },
  {
    // P-256 public key
    curve: CURVE_P256,
    algorithms: [ALGORITHM_ECDH, ALGORITHM_ECDSA],
    isPublic: true,
    prefix: Chunk.from([
      48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206,
      61, 3, 1, 7, 3, 66, 0, 4
    ])
  },
  {
    // P-384 public key
    curve: CURVE_P384,
    algorithms: [ALGORITHM_ECDH, ALGORITHM_ECDSA],
    isPublic: true,
    prefix: Chunk.from([
      48, 118, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0,
      34, 3, 98, 0, 4
    ])
  },
  {
    // P-521 public key
    curve: CURVE_P521,
    algorithms: [ALGORITHM_ECDH, ALGORITHM_ECDSA],
    isPublic: true,
    prefix: Chunk.from([
      48, 129, 155, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4,
      0, 35, 3, 129, 134, 0, 4
    ])
  },
  // X25519 private key
  {
    curve: CURVE_CURVE25519,
    algorithms: [ALGORITHM_ECDH],
    isPublic: false,
    prefix: Chunk.from([
      48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32
    ])
  },
  {
    // Ed25519 private key
    curve: CURVE_CURVE25519,
    algorithms: [ALGORITHM_EDDSA],
    isPublic: false,
    prefix: Chunk.from([
      48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32
    ])
  },
  {
    // X25519 public key
    curve: CURVE_CURVE25519,
    algorithms: [ALGORITHM_ECDH],
    isPublic: true,
    prefix: Chunk.from([48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0])
  },
  {
    // Ed25519 public key
    curve: CURVE_CURVE25519,
    algorithms: [ALGORITHM_EDDSA],
    isPublic: true,
    prefix: Chunk.from([48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0])
  }
]

const emptyPrefix: KeyPrefix = {
  curve: '',
  algorithms: [],
  isPublic: true,
  prefix: Chunk.from([])
}

const findKeyPrefix = (prefixedKey: Uint8Array) => {
  const key = createFrom(prefixedKey)
  const index = prefixes.findIndex(({ prefix }) => key.startsWith(prefix))
  return index >= 0 ? prefixes[index] : { ...emptyPrefix }
}

const findPrefix = (
  curve: string,
  isSigningKey: boolean,
  isPublicKey: boolean
) => {
  const algorithm = getAlgorithm(curve, isSigningKey)
  const index = prefixes.findIndex(
    (prefix) =>
      prefix.curve === curve &&
      prefix.algorithms.includes(algorithm) &&
      prefix.isPublic === isPublicKey
  )
  /* istanbul ignore next */
  return index >= 0 ? prefixes[index] : { ...emptyPrefix }
}

const getAlgorithm = (curve: string, isSigningKey: boolean) => {
  if (isSigningKey) {
    return curve === CURVE_CURVE25519 ? ALGORITHM_EDDSA : ALGORITHM_ECDSA
  }
  return ALGORITHM_ECDH
}

export const addKeyPrefix = (
  curve: string,
  key: Uint8Array,
  isSigningKey: boolean,
  isPublicKey: boolean
) => {
  const { prefix } = findPrefix(curve, isSigningKey, isPublicKey)
  return concat([prefix, key])
}

export const removeKeyPrefix = (key: Uint8Array) => {
  const { prefix } = findKeyPrefix(key)
  return key.subarray(prefix.byteLength)
}

export const identifyCurve = (key: BufferSource) => {
  const { curve } = findKeyPrefix(createFrom(key))
  return curve
    ? Promise.resolve(curve)
    : Promise.reject(new Error('Unsupported key'))
}

export const getCurves = () => curves

export const getHashForCurve = (curve: string) => curveHashes.get(curve)

const isSupportedCurve = (curve: string) => getCurves().includes(curve)

export const ensureSupportedCurve = (curve: string) =>
  isSupportedCurve(curve)
    ? Promise.resolve(curve)
    : Promise.reject(new Error('Unsupported elliptic curve'))

export const ensureSupportedKey = (key: BufferSource) => {
  const k = createFrom(key)
  const { curve } = findKeyPrefix(k)
  return curve
    ? Promise.resolve(k)
    : Promise.reject(new Error('Unsupported key'))
}
