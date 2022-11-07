import { ensureView, ViewLike } from './utils'

type LeadingByteState = [number, boolean]

const countLeadingBytes = (view: Uint8Array, byte: number, right: boolean) => {
  const reducer = (
    [count, isLeadingByte]: LeadingByteState,
    currentByte: number
  ): LeadingByteState => {
    if (isLeadingByte && currentByte === byte) {
      return [count + 1, true]
    }
    return [count, false]
  }
  const initialState: LeadingByteState = [0, true]
  const [count] = right
    ? view.reduceRight(reducer, initialState)
    : view.reduce(reducer, initialState)
  return count
}

const trim = (input: ViewLike, byte: number, right: boolean) => {
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

export const trimLeft = (view: ViewLike, byte = 0) => trim(view, byte, false)

export const trimRight = (view: ViewLike, byte = 0) => trim(view, byte, true)
