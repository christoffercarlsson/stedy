import {
  getBase32Alphabet,
  getBase64Alphabet,
  matchesBase32Alphabet,
  matchesBase64Alphabet
} from './alphabet'
import { splitString } from '../utils'
import {
  BASE32_CHUNK_SIZE_STRING,
  BASE32_MAX_PADDING,
  BASE64_CHUNK_SIZE_STRING,
  BASE64_MAX_PADDING
} from '../constants'

const removeWhitespace = (str: string) => (str || '').replace(/\s+/g, '')

export const removePadding = (str: string) => str.replace(/=+/g, '')

const ensureValidString = (
  input: string,
  chunkSize: number,
  maxPadding: number
) => {
  const str = removePadding(input)
  const remainder = str.length % chunkSize
  if (remainder === 0) {
    return str
  }
  const padLength = chunkSize - remainder
  if (padLength > maxPadding) {
    return ''
  }
  return `${str}${'='.repeat(padLength)}`
}

const decode = (
  str: string,
  chunkSize: number,
  maxPadding: number,
  stringToBytes: (str: string) => number[]
) => {
  return Uint8Array.from(
    splitString(ensureValidString(str, chunkSize, maxPadding), chunkSize)
      .map((chunk) => stringToBytes(chunk))
      .flat()
  )
}

const stringToIndicies = (alphabet: string, str: string) =>
  [...str].map((character) => alphabet.indexOf(character))

export const base32Decode = (input: string) => {
  const str = removeWhitespace(input)
  if (!matchesBase32Alphabet(str)) {
    return Uint8Array.from([])
  }
  const alphabet = getBase32Alphabet()
  return decode(str, BASE32_CHUNK_SIZE_STRING, BASE32_MAX_PADDING, (chunk) => {
    const [a, b, c, d, e, f, g, h] = stringToIndicies(alphabet, chunk)
    const firstByte = (a << 3) | (b >> 2)
    const secondByte = ((b & 3) << 6) | (c << 1) | (d >> 4)
    const thirdByte = ((d & 15) << 4) | (e >> 1)
    const fourthByte = ((e & 1) << 7) | (f << 2) | (g >> 3)
    const fifthByte = ((g & 7) << 5) | h
    if (c === 32) {
      return [firstByte]
    }
    if (e === 32) {
      return [firstByte, secondByte]
    }
    if (f === 32) {
      return [firstByte, secondByte, thirdByte]
    }
    if (h === 32) {
      return [firstByte, secondByte, thirdByte, fourthByte]
    }
    return [firstByte, secondByte, thirdByte, fourthByte, fifthByte]
  })
}

export const base64Decode = (input: string, urlSafe = false) => {
  const str = removeWhitespace(input)
  if (!matchesBase64Alphabet(urlSafe, str)) {
    return Uint8Array.from([])
  }
  const alphabet = getBase64Alphabet(urlSafe)
  return decode(str, BASE64_CHUNK_SIZE_STRING, BASE64_MAX_PADDING, (chunk) => {
    const [a, b, c, d] = stringToIndicies(alphabet, chunk)
    const firstByte = (a << 2) | (b >> 4)
    const secondByte = ((b & 15) << 4) | (c >> 2)
    const thirdByte = ((c & 3) << 6) | d
    if (c === 64) {
      return [firstByte]
    }
    if (d === 64) {
      return [firstByte, secondByte]
    }
    return [firstByte, secondByte, thirdByte]
  })
}
