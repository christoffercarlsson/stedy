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

export const fromString = (input: string, encoding = ENCODING_UTF8) => {
  const str = input || ''
  if (encoding === ENCODING_BASE64) {
    return base64Decode(str, false)
  }
  if (encoding === ENCODING_BASE64_URLSAFE) {
    return base64Decode(str, true)
  }
  if (encoding === ENCODING_HEX) {
    return hexDecode(str)
  }
  if (encoding === ENCODING_JSON) {
    return jsonDecode(str)
  }
  if (encoding === ENCODING_PEM) {
    return pemDecode(str)
  }
  if (encoding === ENCODING_UTF8) {
    return utf8Decode(str)
  }
  return Uint8Array.from([])
}

const ensureString = (value: string | ArrayBufferView) => {
  if (typeof value === 'string') {
    return value
  }
  return utf8Encode(ensureView(value))
}

const decode = (data: string | ArrayBufferView, encoding?: string) =>
  fromString(ensureString(data), encoding)

export default decode
