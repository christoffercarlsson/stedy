import { fromString } from './decode.js'
import { ensureView } from './utils.js'

const createFrom = (value, encoding) => {
  if (typeof value === 'string') {
    return fromString(value, encoding)
  }
  if (
    value !== undefined &&
    value !== null &&
    !ArrayBuffer.isView(value) &&
    typeof value[Symbol.iterator] === 'function'
  ) {
    return Uint8Array.from(value)
  }
  return ensureView(value)
}

export default createFrom
