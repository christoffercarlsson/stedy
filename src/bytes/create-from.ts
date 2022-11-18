import { fromString } from './decode'

const createFrom = (
  value?: string | Iterable<number> | BufferSource,
  encoding?: string
) => {
  if (typeof value === 'string') {
    return fromString(value, encoding)
  }
  if (ArrayBuffer.isView(value)) {
    return value
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
