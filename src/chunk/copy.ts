import createFrom from './create-from'
import { ensureView } from './utils'

const copy = (view: ArrayBufferView) => createFrom([...ensureView(view)])

export default copy
