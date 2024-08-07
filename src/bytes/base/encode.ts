import { getBase32Alphabet, getBase64Alphabet } from './alphabet'
import { removePadding } from './decode'
import split from '../split'
import { BASE32_CHUNK_SIZE_BYTES, BASE64_CHUNK_SIZE_BYTES } from '../constants'

const indicesToCharacters = (alphabet: string, indices: number[]) =>
  indices.map((index) => alphabet.charAt(index))

const encode = (
  view: Uint8Array,
  chunkSize: number,
  withPadding: boolean,
  bytesToCharacters: (chunk: Uint8Array) => string[]
) => {
  const result = split(view, chunkSize)
    .map((chunk) => bytesToCharacters(chunk))
    .flat()
    .join('')
  return withPadding === true ? result : removePadding(result)
}

export const base32Encode = (view: Uint8Array) => {
  const alphabet = getBase32Alphabet()
  return encode(view, BASE32_CHUNK_SIZE_BYTES, true, (chunk) => {
    const [firstByte, secondByte, thirdByte, fourthByte, fifthByte] = chunk
    if (Number.isInteger(fifthByte)) {
      return indicesToCharacters(alphabet, [
        firstByte >> 3,
        ((firstByte & 7) << 2) | (secondByte >> 6),
        (secondByte & 63) >> 1,
        ((secondByte & 1) << 4) | (thirdByte >> 4),
        ((thirdByte & 15) << 1) | (fourthByte >> 7),
        (fourthByte & 127) >> 2,
        ((fourthByte & 3) << 3) | (fifthByte >> 5),
        fifthByte & 31
      ])
    }
    if (Number.isInteger(fourthByte)) {
      return indicesToCharacters(alphabet, [
        firstByte >> 3,
        ((firstByte & 7) << 2) | (secondByte >> 6),
        (secondByte & 63) >> 1,
        ((secondByte & 1) << 4) | (thirdByte >> 4),
        ((thirdByte & 15) << 1) | (fourthByte >> 7),
        (fourthByte & 127) >> 2,
        (fourthByte & 3) << 3,
        32
      ])
    }
    if (Number.isInteger(thirdByte)) {
      return indicesToCharacters(alphabet, [
        firstByte >> 3,
        ((firstByte & 7) << 2) | (secondByte >> 6),
        (secondByte & 63) >> 1,
        ((secondByte & 1) << 4) | (thirdByte >> 4),
        (thirdByte & 15) << 1,
        32,
        32,
        32
      ])
    }
    if (Number.isInteger(secondByte)) {
      return indicesToCharacters(alphabet, [
        firstByte >> 3,
        ((firstByte & 7) << 2) | (secondByte >> 6),
        (secondByte & 63) >> 1,
        (secondByte & 1) << 4,
        32,
        32,
        32,
        32
      ])
    }
    return indicesToCharacters(alphabet, [
      firstByte >> 3,
      (firstByte & 7) << 2,
      32,
      32,
      32,
      32,
      32,
      32
    ])
  })
}

export const base64Encode = (
  view: Uint8Array,
  urlSafe = false,
  withPadding = true
) => {
  const alphabet = getBase64Alphabet(urlSafe)
  return encode(view, BASE64_CHUNK_SIZE_BYTES, withPadding, (chunk) => {
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
  })
}
