import getBytes from './get-bytes'

const copy = (view: BufferSource) => Uint8Array.from(getBytes(view))

export default copy
