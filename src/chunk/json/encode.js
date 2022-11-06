import { createJSONObject } from '../utils'

const encode = (view) => {
  if (view.byteLength === 0) {
    return ''
  }
  return JSON.stringify(createJSONObject(view))
}

export default encode
