import createFrom from './create-from'
import { ensureView, ViewLike } from './utils'

const copy = (view: ViewLike) => createFrom([...ensureView(view)])

export default copy
