import decode from './decode'
import encode from './encode'

const transcode = (
  data: string | ArrayBufferView,
  currentEncoding: string,
  targetEncoding: string
) => encode(decode(data, currentEncoding), targetEncoding)

export default transcode
