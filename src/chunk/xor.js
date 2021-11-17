import alloc from './alloc.js'
import concat from './concat.js'
import { readUint32BE, writeUint32BE } from './numbers.js'
import { padLeft } from './pad.js'
import { ensureView } from './utils.js'

const ensureMultiple = (view, size) => {
  const remainder = view.byteLength % size
  if (remainder === 0) {
    return view
  }
  return padLeft(view, view.byteLength + (size - remainder))
}

const ensureValidInput = (view) =>
  view.byteLength === 0 ? alloc(4) : ensureMultiple(view, 4)

const ensureMatchingInput = (left, right) => {
  const a = ensureValidInput(left)
  const b = ensureValidInput(right)
  if (b.byteLength > a.byteLength) {
    return [padLeft(a, b.byteLength), b]
  }
  return [a, padLeft(b, a.byteLength)]
}

const calculate = (left, right) =>
  concat(
    Array.from({ length: left.byteLength / 4 }, (_, i) => {
      const offset = i * 4
      const result = readUint32BE(left, offset) ^ readUint32BE(right, offset)
      return writeUint32BE(alloc(4), result)
    })
  )

const xor = (a, b) => {
  const left = ensureView(a)
  const right = ensureView(b)
  const size = Math.max(left.byteLength, right.byteLength)
  const result = calculate(...ensureMatchingInput(left, right))
  return result.subarray(result.byteLength - size)
}

export default xor
