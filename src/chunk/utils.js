export const countChunks = (totalSize, chunkSize, appendRemainder) => {
  if (totalSize === 0) {
    return 0
  }
  if (totalSize <= chunkSize) {
    return 1
  }
  const size = totalSize / chunkSize
  return appendRemainder === true ? Math.floor(size) : Math.ceil(size)
}

export const createJSONObject = (view) => ({
  type: 'Buffer',
  data: [...view]
})

export const ensureView = (view) => {
  if (view instanceof ArrayBuffer) {
    return new Uint8Array(view)
  }
  if (ArrayBuffer.isView(view)) {
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength)
  }
  return Uint8Array.from([])
}

export const splitString = (string, size) => {
  const length = countChunks(string.length, size, false)
  return Array.from({ length }, (_, index) => string.substr(index * size, size))
}
