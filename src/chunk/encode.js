import base64Encode from './base64/encode.js'
import {
  ENCODING_BASE64,
  ENCODING_BASE64_URLSAFE,
  ENCODING_HEX,
  ENCODING_JSON,
  ENCODING_PEM,
  ENCODING_UTF8
} from './constants.js'
import hexEncode from './hex/encode.js'
import jsonEncode from './json/encode.js'
import pemEncode from './pem/encode.js'
import utf8Decode from './utf8/decode.js'
import utf8Encode from './utf8/encode.js'
import { ensureView } from './utils.js'

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
