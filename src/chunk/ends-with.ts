import equals from './equals'
import { ensureView, ViewLike } from './utils'

const endsWith = (view: ViewLike, end: ViewLike) => {
  const a = ensureView(view)
  const b = ensureView(end)
  return (
    (a.byteLength === 0 && b.byteLength === 0) ||
    (a.byteLength >= b.byteLength &&
      b.byteLength > 0 &&
      equals(a.subarray(a.byteLength - b.byteLength), b))
  )
}

export default endsWith
