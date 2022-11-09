import { ensureView } from './utils'

const hasSize = (view: ArrayBufferView, size: number) =>
  ensureView(view).byteLength === size

export default hasSize
