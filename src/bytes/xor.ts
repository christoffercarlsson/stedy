import alloc from './alloc'
import concat from './concat'
import { readUint32BE, writeUint32BE } from './numbers'
import { padLeft } from './pad'
import { ensureView } from './utils'

const ensureMultiple = (view: Uint8Array, size: number) => {
  const remainder = view.byteLength % size
  if (remainder === 0) {
    return view
  }
  return padLeft(view, view.byteLength + (size - remainder))
}

const ensureValidInput = (input: BufferSource) => {
  const view = ensureView(input)
  return view.byteLength === 0 ? alloc(4) : ensureMultiple(view, 4)
}

const ensureMatchingInput = (a: Uint8Array, b: Uint8Array) => {
  const left = ensureValidInput(a)
  const right = ensureValidInput(b)
  if (right.byteLength > left.byteLength) {
    return [padLeft(left, right.byteLength), right]
  }
  return [left, padLeft(right, left.byteLength)]
}

const calculate = (a: Uint8Array, b: Uint8Array) => {
  const [left, right] = ensureMatchingInput(a, b)
  return concat(
    Array.from({ length: left.byteLength / 4 }, (_, i) => {
      const offset = i * 4
      const result = readUint32BE(left, offset) ^ readUint32BE(right, offset)
      return writeUint32BE(alloc(4), result)
    })
  )
}

const xor = (a: BufferSource, b: BufferSource) => {
  const left = ensureView(a)
  const right = ensureView(b)
  const size = Math.max(left.byteLength, right.byteLength)
  const result = calculate(left, right)
  return result.subarray(result.byteLength - size)
}

export default xor
