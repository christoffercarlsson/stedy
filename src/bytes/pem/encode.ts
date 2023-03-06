import { base64Encode } from '../base/encode'
import { splitString } from '../utils'

const normalizeLabel = (label: string) =>
  String(label).replace('-', ' ').replace(/\s+/g, ' ').trim().toUpperCase()

const encodeData = (view: Uint8Array) =>
  splitString(base64Encode(view), 64).join('\n')

const encode = (view: Uint8Array, pemLabel: string) => {
  if (view.byteLength === 0) {
    return ''
  }
  const label = normalizeLabel(pemLabel)
  const data = encodeData(view)
  return `-----BEGIN ${label}-----\n${data}\n-----END ${label}-----`
}

export default encode
