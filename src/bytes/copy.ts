import getBytes from './get-bytes'

const copy = (view: ArrayBufferView) => Uint8Array.from(getBytes(view))

export default copy
