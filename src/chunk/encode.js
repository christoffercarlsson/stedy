import base64Encode from './base64/encode'
import {
  ENCODING_BASE64,
  ENCODING_BASE64_URLSAFE,
  ENCODING_HEX,
  ENCODING_JSON,
  ENCODING_PEM,
  ENCODING_UTF8
} from './constants'
import hexEncode from './hex/encode'
import jsonEncode from './json/encode'
import pemEncode from './pem/encode'
import utf8Decode from './utf8/decode'
import utf8Encode from './utf8/encode'
import { ensureView } from './utils'

export const toString = (data, encoding = ENCODING_UTF8, label = '') => {
  const view = ensureView(data)
  if (encoding === ENCODING_BASE64) {
    return base64Encode(view, false)
  }
  if (encoding === ENCODING_BASE64_URLSAFE) {
    return base64Encode(view, true)
  }
  if (encoding === ENCODING_HEX) {
    return hexEncode(view)
  }
  if (encoding === ENCODING_JSON) {
    return jsonEncode(view)
  }
  if (encoding === ENCODING_PEM) {
    return pemEncode(view, label)
  }
  if (encoding === ENCODING_UTF8) {
    return utf8Encode(view)
  }
  return ''
}

const encode = (data, encoding, label) =>
  utf8Decode(toString(data, encoding, label))

export default encode
