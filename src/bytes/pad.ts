import alloc from './alloc'
import concat from './concat'
import { ensureView } from './utils'

const pad = (input: BufferSource, size: number, right: boolean) => {
  const view = ensureView(input)
  if (view.byteLength >= size) {
    return view
  }
  const padding = alloc(size - view.byteLength)
  return concat(right ? [view, padding] : [padding, view])
}

export const padLeft = (view: BufferSource, size: number) =>
  pad(view, size, false)

export const padRight = (view: BufferSource, size: number) =>
  pad(view, size, true)
