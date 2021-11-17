import createFrom from './create-from.js'
import { ensureView } from './utils.js'

const copy = (view) => createFrom([...ensureView(view)])

export default copy
