import { getAlphabet, matchesAlphabet } from './alphabet'
import { splitString } from '../utils'

const removeWhitespace = (string) => string.replace(/\s+/g, '')

export const removePadding = (string) => string.replace(/=+/g, '')

const ensureValidString = (input, urlSafe) => {
  if (!matchesAlphabet(input, urlSafe)) {
    return ''
  }
  const string = removePadding(input)
  const remainder = string.length % 4
  if (remainder === 0) {
    return string
  }
  const padLength = 4 - remainder
  if (padLength === 3) {
    return ''
  }
  return `${string}${'='.repeat(padLength)}`
}

const stringToBytes = (alphabet, string) => {
  const [a, b, c, d] = [...string].map((character) =>
    alphabet.indexOf(character)
  )
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
}

const decode = (string, urlSafe = false) => {
  const alphabet = getAlphabet(urlSafe)
  return Uint8Array.from(
    splitString(ensureValidString(removeWhitespace(string), urlSafe), 4)
      .map((str) => stringToBytes(alphabet, str))
      .flat()
  )
}

export default decode
