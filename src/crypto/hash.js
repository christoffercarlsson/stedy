import { createFrom } from '../chunk'
import { ensureSupportedHash } from './utils'

const iterateHash = async (crypto, algorithm, message, iterations) => {
  const digest = await crypto.subtle.digest(algorithm, message)
  const iterationsLeft = iterations - 1
  if (iterationsLeft === 0) {
    return digest
  }
  return iterateHash(crypto, algorithm, digest, iterationsLeft)
}

const hash = async (crypto, algorithm, message, iterations) =>
  createFrom(
    await iterateHash(
      crypto,
      await ensureSupportedHash(algorithm),
      createFrom(message),
      Number.isInteger(iterations) && iterations > 0 ? iterations : 1
    )
  )

export default hash
