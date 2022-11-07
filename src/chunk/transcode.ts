import decode from './decode'
import encode from './encode'
import { ViewLike } from './utils'

const transcode = (
  data: string | ViewLike,
  currentEncoding: string,
  targetEncoding: string
) => encode(decode(data, currentEncoding), targetEncoding)

export default transcode
