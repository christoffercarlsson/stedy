import { ensureView } from './utils.js'

const hasSize = (view, size) => ensureView(view).byteLength === size

export default hasSize
