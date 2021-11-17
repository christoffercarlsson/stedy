import decode from './decode.js'
import encode from './encode.js'

const transcode = (data, currentEncoding, targetEncoding) =>
  encode(decode(data, currentEncoding), targetEncoding)

export default transcode
