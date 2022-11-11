const ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
const ALPHABET_URL = ALPHABET.replace('+', '-').replace('/', '_')

const getBaseAlphabet = (urlSafe: boolean) =>
  urlSafe === true ? ALPHABET_URL : ALPHABET

export const getAlphabet = (urlSafe: boolean) => `${getBaseAlphabet(urlSafe)}=`

export const matchesAlphabet = (str: string, urlSafe: boolean) => {
  const characterSet = getBaseAlphabet(urlSafe).replace('-', '\\-')
  const regexp = new RegExp(`^[${characterSet}]+={0,2}$`, 'g')
  return regexp.test(str)
}
