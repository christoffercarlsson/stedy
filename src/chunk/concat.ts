import getBytes from './get-bytes'
import { ViewLike } from './utils'

const concat = (views: ViewLike[]) =>
  Uint8Array.from(views.map((view) => getBytes(view)).flat())

export default concat
