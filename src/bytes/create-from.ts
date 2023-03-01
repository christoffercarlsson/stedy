import { fromString } from './decode'
import { fromInteger } from './numbers'

const createFrom = (
  value?: string | number | Iterable<number> | BufferSource,
  encoding?: string
) => {
  if (typeof value === 'string') {
    return fromString(value, encoding)
  }
  if (typeof value === 'number') {
    return fromInteger(value)
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value)
  }
  if (
    value !== undefined &&
    value !== null &&
    !(value instanceof ArrayBuffer) &&
    !ArrayBuffer.isView(value) &&
    typeof value[Symbol.iterator] === 'function'
  ) {
    return Uint8Array.from(value)
  }
  return Uint8Array.from([])
}

export default createFrom
