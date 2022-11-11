import hasSize from './has-size'

const isEmpty = (view: ArrayBufferView) => hasSize(view, 0)

export default isEmpty
