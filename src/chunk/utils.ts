export type ViewLike = ArrayBuffer | ArrayBufferView

export const countChunks = (
  totalSize: number,
  chunkSize: number,
  appendRemainder = false
) => {
  if (totalSize === 0) {
    return 0
  }
  if (totalSize <= chunkSize) {
    return 1
  }
  const size = totalSize / chunkSize
  return appendRemainder === true ? Math.floor(size) : Math.ceil(size)
}

export const createJSONObject = (view: Uint8Array) => ({
  type: 'Buffer',
  data: [...view]
})

export const ensureView = (view: ViewLike) => {
  if (view instanceof ArrayBuffer) {
    return new Uint8Array(view)
  }
  if (ArrayBuffer.isView(view)) {
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength)
  }
  return Uint8Array.from([])
}

export const splitString = (str: string, size: number) => {
  const length = countChunks(str.length, size, false)
  return Array.from({ length }, (_, index) => {
    const begin = index * size
    const end = begin + size
    return str.slice(begin, end)
  })
}
