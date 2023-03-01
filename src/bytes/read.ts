import { ensureView } from './utils'

const calculateSlices = (sizes: number[]) =>
  sizes.slice(1).reduce(
    (slices, size) => {
      const begin = slices[slices.length - 1][1]
      const end = begin + size
      return [...slices, [begin, end]]
    },
    [[0, sizes[0]]]
  )

const calculateEnd = (sizes: number[]) =>
  sizes.reduce((sum, size) => sum + size)

const read = (chunk: BufferSource, ...sizes: number[]) => {
  const view = ensureView(chunk)
  const views = calculateSlices(sizes).map(([begin, end]) =>
    view.subarray(begin, end)
  )
  return [...views, view.subarray(calculateEnd(sizes))]
}

export default read
