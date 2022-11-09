import { createFrom } from '../chunk'
import { ensureSupportedHash, WebCrypto } from './utils'

const iterateHash = async (
  crypto: WebCrypto,
  algorithm: string,
  message: BufferSource,
  iterations: number
): Promise<ArrayBuffer> => {
  const digest = await crypto.subtle.digest(algorithm, message)
  const iterationsLeft = iterations - 1
  if (iterationsLeft === 0) {
    return digest
  }
  return iterateHash(crypto, algorithm, digest, iterationsLeft)
}

const hash = async (
  crypto: WebCrypto,
  algorithm: string,
  message: BufferSource,
  iterations?: number
) =>
  createFrom(
    await iterateHash(
      crypto,
      await ensureSupportedHash(algorithm),
      createFrom(message),
      Number.isInteger(iterations) && iterations > 0 ? iterations : 1
    )
  )

export default hash
