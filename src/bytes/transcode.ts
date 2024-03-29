import decode from './decode'
import encode from './encode'

const transcode = (
  view: BufferSource,
  currentEncoding: string,
  targetEncoding: string
) => encode(decode(view, currentEncoding), targetEncoding)

export default transcode
