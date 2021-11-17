import getBytes from '../get-bytes.js'

const encode = (view) =>
  getBytes(view)
    .map((byte) => byte.toString(16))
    .join('')

export default encode
