import equals from './equals'
import { ensureView } from './utils'

const startsWith = (view: ArrayBufferView, start: ArrayBufferView) => {
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
