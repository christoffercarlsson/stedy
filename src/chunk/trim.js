import { ensureView } from './utils'

const countLeadingBytes = (view, byte, right) => {
  const initialState = [0, true]
  const reducer = ([count, isLeadingZero], value) => {
    if (isLeadingZero && value === byte) {
      return [count + 1, true]
    }
    return [count, false]
  }
  const state = right
    ? view.reduceRight(reducer, initialState)
    : view.reduce(reducer, initialState)
  return state[0]
}

const trim = (input, byte, right) => {
  const view = ensureView(input)
  const count = countLeadingBytes(
    view,
    Number.isInteger(byte) && byte >= 0 && byte < 256 ? byte : 0,
    right
  )
  return right
    ? view.subarray(0, view.byteLength - count)
    : view.subarray(count)
}

export const trimLeft = (view, byte = 0) => trim(view, byte, false)

export const trimRight = (view, byte = 0) => trim(view, byte, true)
