import equals from './equals'
import { ensureView } from './utils'

const startsWith = (view: BufferSource, start: BufferSource) => {
  const a = ensureView(view)
  const b = ensureView(start)
  return (
    (a.byteLength === 0 && b.byteLength === 0) ||
    (a.byteLength >= b.byteLength &&
      b.byteLength > 0 &&
      equals(a.subarray(0, b.byteLength), b))
  )
}

export default startsWith
