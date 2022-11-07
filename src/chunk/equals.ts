import { ensureView, ViewLike } from './utils'

const equals = (view: ViewLike, value: ViewLike) => {
  const a = ensureView(view)
  const b = ensureView(value)
  return (
    a.byteLength === b.byteLength && a.every((byte, index) => byte === b[index])
  )
}

export default equals
