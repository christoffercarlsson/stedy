const ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
const ALPHABET_URL = ALPHABET.replace('+', '-').replace('/', '_')

const getBaseAlphabet = (urlSafe) =>
  urlSafe === true ? ALPHABET_URL : ALPHABET

export const getAlphabet = (urlSafe) => `${getBaseAlphabet(urlSafe)}=`

export const matchesAlphabet = (string, urlSafe) => {
  const characterSet = getBaseAlphabet(urlSafe).replace('-', '\\-')
  const regexp = new RegExp(`^[${characterSet}]+={0,2}$`, 'g')
  return regexp.test(string)
}
