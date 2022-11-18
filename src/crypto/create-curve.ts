import { Chunk } from '../bytes'
import diffieHellman from './diffie-hellman'
import generateKeyPair from './generate-key-pair'
import generateSignKeyPair from './generate-sign-key-pair'
import importKey from './import-key'
import sign from './sign'
import { getCrypto, getHashForCurve } from './utils'
import verify from './verify'

export type DiffieHellmanFunction = (
  ourPrivateKey: BufferSource,
  theirPublicKey: BufferSource,
  size?: number
) => Promise<Chunk>

export type GenerateKeyPairFunction = () => Promise<{
  publicKey: Chunk
  privateKey: Chunk
}>

export type ImportKeyFunction = (
  key: BufferSource,
  isSigningKey: boolean,
  isPublicKey: boolean
) => Promise<Chunk>

export type SignFunction = (
  privateKey: BufferSource,
  message: BufferSource
) => Promise<Chunk>

export type VerifyFunction = (
  message: BufferSource,
  publicKey: BufferSource,
  signature: BufferSource
) => Promise<boolean>

export type CurveFunctions = {
  diffieHellman: DiffieHellmanFunction
  generateKeyPair: GenerateKeyPairFunction
  generateSignKeyPair: GenerateKeyPairFunction
  importKey: ImportKeyFunction
  sign: SignFunction
  verify: VerifyFunction
}

const createCurve = (curve: string, hash?: string): CurveFunctions => {
  const curveHash = hash || getHashForCurve(curve)
  return {
    diffieHellman: async (
      ourPrivateKey: BufferSource,
      theirPublicKey: BufferSource,
      size?: number
    ) => diffieHellman(await getCrypto(), ourPrivateKey, theirPublicKey, size),

    generateKeyPair: async () => generateKeyPair(await getCrypto(), curve),

    generateSignKeyPair: async () =>
      generateSignKeyPair(await getCrypto(), curve),

    importKey: (
      key: BufferSource,
      isSigningKey: boolean,
      isPublicKey: boolean
    ) => importKey(curve, key, isSigningKey, isPublicKey),

    sign: async (message: BufferSource, privateKey: BufferSource) =>
      sign(await getCrypto(), message, privateKey, curveHash),

    verify: async (
      message: BufferSource,
      publicKey: BufferSource,
      signature: BufferSource
    ) => verify(await getCrypto(), message, publicKey, signature, curveHash)
  }
}

export default createCurve
