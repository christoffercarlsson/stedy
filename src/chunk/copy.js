import createFrom from './create-from'
import { ensureView } from './utils'

const copy = (view) => createFrom([...ensureView(view)])

export default copy
