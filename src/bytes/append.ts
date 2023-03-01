import concat from './concat'

const append = (a: BufferSource, b: BufferSource) => concat([a, b])

export default append
