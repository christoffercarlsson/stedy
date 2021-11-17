import base64Encode from '../base64/encode.js'
import { splitString } from '../utils.js'

const normalizeLabel = (label) =>
  String(label).replace('-', ' ').replace(/\s+/g, ' ').trim().toUpperCase()

const encodeData = (view) => splitString(base64Encode(view), 64).join('\n')

const encode = (view, pemLabel) => {
  if (view.byteLength === 0) {
    return ''
  }
  const label = normalizeLabel(pemLabel)
  const data = encodeData(view)
  return `-----BEGIN ${label}-----\n${data}\n-----END ${label}-----`
}

export default encode
