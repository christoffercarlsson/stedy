import hasSize from './has-size'
import { ViewLike } from './utils'

const isEmpty = (view: ViewLike) => hasSize(view, 0)

export default isEmpty
