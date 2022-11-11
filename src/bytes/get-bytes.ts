import { ensureView } from './utils'

const getBytes = (view: ArrayBufferView) => [...ensureView(view)]

export default getBytes
