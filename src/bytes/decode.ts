import { base32Decode, base64Decode } from './base/decode'
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
import hexDecode from './hex/decode'
import jsonDecode from './json/decode'
import pemDecode from './pem/decode'
import utf8Decode from './utf8/decode'
import utf8Encode from './utf8/encode'
import { ensureView } from './utils'

export const fromString = (input: string, encoding = ENCODING_UTF8) => {
  const str = input || ''
  if (encoding === ENCODING_BASE32) {
    return base32Decode(str)
  }
  if (encoding === ENCODING_BASE64 || encoding === ENCODING_BASE64_UNPADDED) {
    return base64Decode(str, false)
  }
  if (
    encoding === ENCODING_BASE64_URL ||
    encoding === ENCODING_BASE64_URL_UNPADDED
  ) {
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

const decode = (view: BufferSource, encoding?: string) => {
  const str = utf8Encode(ensureView(view))
  return fromString(str, encoding)
}

export default decode
