import { ensureView } from './utils'

const getBytes = (view: BufferSource) => [...ensureView(view)]

export default getBytes
