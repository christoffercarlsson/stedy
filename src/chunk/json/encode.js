import { createJSONObject } from '../utils.js'

const encode = (view) => {
  if (view.byteLength === 0) {
    return ''
  }
  return JSON.stringify(createJSONObject(view))
}

export default encode
