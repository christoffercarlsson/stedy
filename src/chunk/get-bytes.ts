import { ensureView, ViewLike } from './utils'

const getBytes = (view: ViewLike) => [...ensureView(view)]

export default getBytes
