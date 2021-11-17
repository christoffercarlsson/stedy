import { ensureView } from './utils.js'

const calculateSlices = (sizes) =>
  sizes.slice(1).reduce(
    (slices, size) => {
      const begin = slices[slices.length - 1][1]
      const end = begin + size
      return [...slices, [begin, end]]
    },
    [[0, sizes[0]]]
  )

const calculateEnd = (sizes) => sizes.reduce((sum, size) => sum + size)

const read = (chunk, ...sizes) => {
  const view = ensureView(chunk)
  const views = calculateSlices(sizes).map(([begin, end]) =>
    view.subarray(begin, end)
  )
  return [...views, view.subarray(calculateEnd(sizes))]
}

export default read
