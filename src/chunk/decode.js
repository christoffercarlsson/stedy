import base64Decode from './base64/decode'
import {
  ENCODING_BASE64,
  ENCODING_BASE64_URLSAFE,
  ENCODING_HEX,
  ENCODING_JSON,
  ENCODING_PEM,
  ENCODING_UTF8
} from './constants'
import hexDecode from './hex/decode'
import jsonDecode from './json/decode'
import pemDecode from './pem/decode'
import utf8Decode from './utf8/decode'
import utf8Encode from './utf8/encode'
import { ensureView } from './utils'

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
