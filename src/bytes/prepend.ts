import append from './append'

const prepend = (a: ArrayBufferView, b: ArrayBufferView) => append(b, a)

export default prepend
