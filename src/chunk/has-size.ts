import { ensureView, ViewLike } from './utils'

const hasSize = (view: ViewLike, size: number) =>
  ensureView(view).byteLength === size

export default hasSize
