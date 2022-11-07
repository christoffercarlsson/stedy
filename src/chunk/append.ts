import concat from './concat'
import { ViewLike } from './utils'

const append = (a: ViewLike, b: ViewLike) => concat([a, b])

export default append
