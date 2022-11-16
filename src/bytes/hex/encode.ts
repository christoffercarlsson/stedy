import getBytes from '../get-bytes'

const encode = (view: Uint8Array) =>
  getBytes(view)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')

export default encode
