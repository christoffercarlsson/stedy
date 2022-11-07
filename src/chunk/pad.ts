import alloc from './alloc'
import concat from './concat'
import { ensureView, ViewLike } from './utils'

const pad = (input: ViewLike, size: number, right: boolean) => {
  const view = ensureView(input)
  if (view.byteLength >= size) {
    return view
  }
  const padding = alloc(size - view.byteLength)
  return concat(right ? [view, padding] : [padding, view])
}

export const padLeft = (view: ViewLike, size: number) => pad(view, size, false)

export const padRight = (view: ViewLike, size: number) => pad(view, size, true)
