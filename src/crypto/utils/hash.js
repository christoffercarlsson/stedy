import {
  HASH_SHA256,
  HASH_SHA256_SIZE,
  HASH_SHA384,
  HASH_SHA384_SIZE,
  HASH_SHA512,
  HASH_SHA512_SIZE
} from '../constants'

const hashSizes = new Map([
  [HASH_SHA256, HASH_SHA256_SIZE],
  [HASH_SHA384, HASH_SHA384_SIZE],
  [HASH_SHA512, HASH_SHA512_SIZE]
])

export const getHashSize = (hash) =>
  hashSizes.has(hash) ? hashSizes.get(hash) : 0

const isSupportedHash = (hash) => hashSizes.has(hash)

export const ensureSupportedHash = (hash) =>
  isSupportedHash(hash)
    ? Promise.resolve(hash)
    : Promise.reject(new Error('Unsupported hash algorithm'))
