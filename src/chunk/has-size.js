import { ensureView } from './utils'

const hasSize = (view, size) => ensureView(view).byteLength === size

export default hasSize
