export const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
export const BASE32_CHUNK_SIZE_BYTES = 5
export const BASE32_CHUNK_SIZE_STRING = 8
export const BASE32_MAX_PADDING = 6
export const BASE64_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
export const BASE64_ALPHABET_URL = BASE64_ALPHABET.replace('+', '-').replace(
  '/',
  '_'
)
export const BASE64_CHUNK_SIZE_BYTES = 3
export const BASE64_CHUNK_SIZE_STRING = 4
export const BASE64_MAX_PADDING = 2
export const ENCODING_BASE32 = 'base32'
export const ENCODING_BASE64 = 'base64'
export const ENCODING_BASE64_URLSAFE = 'base64url'
export const ENCODING_HEX = 'hex'
export const ENCODING_JSON = 'json'
export const ENCODING_PEM = 'pem'
export const ENCODING_UTF8 = 'utf8'
