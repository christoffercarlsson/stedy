import concat from './concat'

const append = (a: ArrayBufferView, b: ArrayBufferView) => concat([a, b])

export default append
