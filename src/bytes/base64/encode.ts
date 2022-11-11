import { getAlphabet } from './alphabet'
import { removePadding } from './decode'
import split from '../split'

const indicesToCharacters = (alphabet: string, indices: number[]) =>
  indices.map((index) => alphabet.charAt(index))

const bytesToCharacters = (alphabet: string, chunk: Uint8Array) => {
  const [firstByte, secondByte, thirdByte] = chunk
  if (Number.isInteger(thirdByte)) {
    return indicesToCharacters(alphabet, [
      firstByte >> 2,
      ((firstByte & 3) << 4) | (secondByte >> 4),
      ((secondByte & 15) << 2) | (thirdByte >> 6),
      thirdByte & 63
    ])
  }
  if (Number.isInteger(secondByte)) {
    return indicesToCharacters(alphabet, [
      firstByte >> 2,
      ((firstByte & 3) << 4) | (secondByte >> 4),
      (secondByte & 15) << 2,
      64
    ])
  }
  return indicesToCharacters(alphabet, [
    firstByte >> 2,
    (firstByte & 3) << 4,
    64,
    64
  ])
}

const encode = (view: Uint8Array, urlSafe = false) => {
  const alphabet = getAlphabet(urlSafe)
  const result = split(view, 3)
    .map((chunk) => bytesToCharacters(alphabet, chunk))
    .flat()
    .join('')
  return urlSafe === true ? removePadding(result) : result
}

export default encode
