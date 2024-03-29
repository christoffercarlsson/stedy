import { ensureView, countChunks } from './utils'

const split = (chunk: BufferSource, size: number, appendRemainder = false) => {
  const view = ensureView(chunk)
  const length = countChunks(view.byteLength, size, appendRemainder)
  return Array.from({ length }, (_, index) => {
    const begin = index * size
    return index + 1 === length
      ? view.subarray(begin)
      : view.subarray(begin, begin + size)
  })
}

export default split
