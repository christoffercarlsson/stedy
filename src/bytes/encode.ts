import { base32Encode, base64Encode } from './base/encode'
import {
  ENCODING_BASE32,
  ENCODING_BASE64,
  ENCODING_BASE64_UNPADDED,
  ENCODING_BASE64_URL,
  ENCODING_BASE64_URL_UNPADDED,
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

export const toString = (
  data: BufferSource,
  encoding = ENCODING_UTF8,
  label = ''
) => {
  const view = ensureView(data)
  if (encoding === ENCODING_BASE32) {
    return base32Encode(view)
  }
  if (encoding === ENCODING_BASE64) {
    return base64Encode(view, false, true)
  }
  if (encoding === ENCODING_BASE64_UNPADDED) {
    return base64Encode(view, false, false)
  }
  if (encoding === ENCODING_BASE64_URL) {
    return base64Encode(view, true, true)
  }
  if (encoding === ENCODING_BASE64_URL_UNPADDED) {
    return base64Encode(view, true, false)
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

const encode = (data: BufferSource, encoding?: string, label?: string) =>
  utf8Decode(toString(data, encoding, label))

export default encode
