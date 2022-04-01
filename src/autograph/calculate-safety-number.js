import { ENCODING_BASE64_URLSAFE, createFrom, split } from '../chunk.js'
import { HASH_SHA512, hash } from '../crypto.js'
import { SAFETY_NUMBER_DIVISOR, SAFETY_NUMBER_ITERATIONS } from './constants.js'
import { ensureValidPublicKey } from './utils.js'

const encodeChunk = (chunk) => {
  const [a, b, c, d, e] = chunk
  const number =
    (a * 2 ** 32 + b * 2 ** 24 + c * 2 ** 16 + d * 2 ** 8 + e) %
    SAFETY_NUMBER_DIVISOR
  const result = number.toString()
  return `${'0'.repeat(5 - result.length)}${result}`
}

const calculate = async (publicKey, encoding) => {
  const digest = await hash(
    HASH_SHA512,
    await ensureValidPublicKey(createFrom(publicKey, encoding)),
    SAFETY_NUMBER_ITERATIONS
  )
  return split(digest.subarray(0, 30), 5)
    .map((chunk) => encodeChunk(chunk))
    .join('')
}

const calculateSafetyNumber = async (
  ourPublicKey,
  theirPublicKey,
  encoding = ENCODING_BASE64_URLSAFE
) => {
  const fingerprints = await Promise.all([
    calculate(ourPublicKey, encoding),
    calculate(theirPublicKey, encoding)
  ])
  return createFrom(fingerprints.sort().join(''))
}

export default calculateSafetyNumber
