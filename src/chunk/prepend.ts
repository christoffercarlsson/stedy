import append from './append'
import { ViewLike } from './utils'

const prepend = (a: ViewLike, b: ViewLike) => append(b, a)

export default prepend
