import base64Decode from './base64/decode.js'
import {
  ENCODING_BASE64,
  ENCODING_BASE64_URLSAFE,
  ENCODING_HEX,
  ENCODING_JSON,
  ENCODING_PEM,
  ENCODING_UTF8
} from './constants.js'
import hexDecode from './hex/decode.js'
import jsonDecode from './json/decode.js'
import pemDecode from './pem/decode.js'
import utf8Decode from './utf8/decode.js'
import utf8Encode from './utf8/encode.js'
import { ensureView } from './utils.js'

export const fromString = (data, encoding = ENCODING_UTF8) => {
  const string = typeof data === 'string' ? data : ''
  if (encoding === ENCODING_BASE64) {
    return base64Decode(string, false)
  }
  if (encoding === ENCODING_BASE64_URLSAFE) {
    return base64Decode(string, true)
  }
  if (encoding === ENCODING_HEX) {
    return hexDecode(string)
  }
  if (encoding === ENCODING_JSON) {
    return jsonDecode(string)
  }
  if (encoding === ENCODING_PEM) {
    return pemDecode(string)
  }
  if (encoding === ENCODING_UTF8) {
    return utf8Decode(string)
  }
  return Uint8Array.from([])
}

const ensureString = (value) => {
  if (typeof value === 'string') {
    return value
  }
  return utf8Encode(ensureView(value))
}

const decode = (data, encoding) => fromString(ensureString(data), encoding)

export default decode
