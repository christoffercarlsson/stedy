import { getAlphabet, matchesAlphabet } from './alphabet'
import { splitString } from '../utils'

const removeWhitespace = (str: string) => str.replace(/\s+/g, '')

export const removePadding = (str: string) => str.replace(/=+/g, '')

const ensureValidString = (input: string, urlSafe: boolean) => {
  if (!matchesAlphabet(input, urlSafe)) {
    return ''
  }
  const str = removePadding(input)
  const remainder = str.length % 4
  if (remainder === 0) {
    return str
  }
  const padLength = 4 - remainder
  if (padLength === 3) {
    return ''
  }
  return `${str}${'='.repeat(padLength)}`
}

const stringToBytes = (alphabet: string, str: string) => {
  const [a, b, c, d] = [...str].map((character) => alphabet.indexOf(character))
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

const decode = (str: string, urlSafe = false) => {
  const alphabet = getAlphabet(urlSafe)
  return Uint8Array.from(
    splitString(ensureValidString(removeWhitespace(str || ''), urlSafe), 4)
      .map((s: string) => stringToBytes(alphabet, s))
      .flat()
  )
}

export default decode
