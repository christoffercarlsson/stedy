import { ensureView } from './utils'

const equals = (view: BufferSource, value: BufferSource) => {
  const a = ensureView(view)
  const b = ensureView(value)
  return (
    a.byteLength === b.byteLength && a.every((byte, index) => byte === b[index])
  )
}

export default equals
