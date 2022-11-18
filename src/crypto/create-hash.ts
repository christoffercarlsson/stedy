import { Chunk } from '../bytes'
import hash from './hash'
import hkdf from './hkdf'
import hmac from './hmac'
import pbkdf2 from './pbkdf2'
import { getCrypto } from './utils'

export type HashFunction = (
  message: BufferSource,
  iterations?: number
) => Promise<Chunk>

export type HKDFFunction = (
  message: BufferSource,
  salt: BufferSource,
  info?: BufferSource,
  size?: number
) => Promise<Chunk>

export type HMACFunction = (
  key: BufferSource,
  message: BufferSource
) => Promise<Chunk>

export type PBKDF2Function = (
  password: BufferSource,
  salt: BufferSource,
  iterations?: number,
  size?: number
) => Promise<Chunk>

export type HashFunctions = {
  hash: HashFunction
  hkdf: HKDFFunction
  hmac: HMACFunction
  pbkdf2: PBKDF2Function
}

const createHash = (algorithm: string): HashFunctions => ({
  hash: async (message: BufferSource, iterations?: number) =>
    hash(await getCrypto(), algorithm, message, iterations),

  hkdf: async (
    message: BufferSource,
    salt: BufferSource,
    info?: BufferSource,
    size?: number
  ) => hkdf(await getCrypto(), algorithm, message, salt, info, size),

  hmac: async (key: BufferSource, message: BufferSource) =>
    hmac(await getCrypto(), algorithm, key, message),

  pbkdf2: async (
    password: BufferSource,
    salt: BufferSource,
    iterations?: number,
    size?: number
  ) => pbkdf2(await getCrypto(), algorithm, password, salt, iterations, size)
})

export default createHash
