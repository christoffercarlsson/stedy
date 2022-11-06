import alloc from './alloc'
import concat from './concat'
import { ensureView } from './utils'

const pad = (input, size, right) => {
  const view = ensureView(input)
  if (view.byteLength >= size) {
    return view
  }
  const padding = alloc(size - view.byteLength)
  return concat(right ? [view, padding] : [padding, view])
}

export const padLeft = (view, size) => pad(view, size, false)

export const padRight = (view, size) => pad(view, size, true)
