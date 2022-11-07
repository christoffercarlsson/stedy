import { fromString } from './decode'
import { ensureView, ViewLike } from './utils'

const createFrom = (
  value?: string | ViewLike | Iterable<number>,
  encoding?: string
) => {
  if (typeof value === 'string') {
    return fromString(value, encoding)
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
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    return ensureView(value)
  }
  return Uint8Array.from([])
}

export default createFrom
