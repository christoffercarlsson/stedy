import { ensureView } from './utils'

const getBytes = (view) => [...ensureView(view)]

export default getBytes
