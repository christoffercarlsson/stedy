import { ensureView } from './utils'

const hasSize = (view: BufferSource, size: number) =>
  ensureView(view).byteLength === size

export default hasSize
