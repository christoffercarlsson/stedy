import decode from './decode'
import encode from './encode'

const transcode = (data, currentEncoding, targetEncoding) =>
  encode(decode(data, currentEncoding), targetEncoding)

export default transcode
