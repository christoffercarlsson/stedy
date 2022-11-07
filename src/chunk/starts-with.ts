import equals from './equals'
import { ensureView, ViewLike } from './utils'

const startsWith = (view: ViewLike, start: ViewLike) => {
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
