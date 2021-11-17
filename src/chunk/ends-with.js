import equals from './equals.js'
import { ensureView } from './utils.js'

const endsWith = (view, end) => {
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
