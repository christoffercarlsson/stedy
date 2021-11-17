import { ensureView } from './utils.js'

const getBytes = (view) => [...ensureView(view)]

export default getBytes
