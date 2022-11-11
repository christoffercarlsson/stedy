import getBytes from './get-bytes'

const concat = (views: ArrayBufferView[]) =>
  Uint8Array.from(views.map((view) => getBytes(view)).flat())

export default concat
