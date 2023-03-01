import append from './append'

const prepend = (a: BufferSource, b: BufferSource) => append(b, a)

export default prepend
