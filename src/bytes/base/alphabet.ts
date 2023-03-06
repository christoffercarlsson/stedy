import {
  BASE32_ALPHABET,
  BASE32_MAX_PADDING,
  BASE64_ALPHABET,
  BASE64_ALPHABET_URL,
  BASE64_MAX_PADDING
} from '../constants'

const getFullAlphabet = (alphabet: string) => `${alphabet}=`

export const getBase32Alphabet = () => getFullAlphabet(BASE32_ALPHABET)

export const getBase64Alphabet = (urlSafe: boolean) =>
  getFullAlphabet(urlSafe === true ? BASE64_ALPHABET_URL : BASE64_ALPHABET)

const matchesAlphabet = (alphabet: string, maxPadding: number, str: string) => {
  const characterSet = alphabet.replace('-', '\\-')
  const regexp = new RegExp(`^[${characterSet}]+={0,${maxPadding}}$`, 'g')
  return regexp.test(str)
}

export const matchesBase32Alphabet = (str: string) =>
  matchesAlphabet(BASE32_ALPHABET, BASE32_MAX_PADDING, str)

export const matchesBase64Alphabet = (urlSafe: boolean, str: string) =>
  matchesAlphabet(
    urlSafe === true ? BASE64_ALPHABET_URL : BASE64_ALPHABET,
    BASE64_MAX_PADDING,
    str
  )
