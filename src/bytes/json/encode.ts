import { createJSONObject } from '../utils'

const encode = (view: Uint8Array) => {
  if (view.byteLength === 0) {
    return ''
  }
  return JSON.stringify(createJSONObject(view))
}

export default encode
