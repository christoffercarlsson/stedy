import hasSize from './has-size'

const isEmpty = (view: BufferSource) => hasSize(view, 0)

export default isEmpty
