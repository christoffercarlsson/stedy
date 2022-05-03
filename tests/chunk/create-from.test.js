import { describe, it, expect } from '../../dist/test.js'
import { createFrom } from '../../dist/chunk.js'

export default describe('createFrom', () => [
  it('should create a new chunk from a typed array', () => {
    const view = Uint16Array.from([1, 2, 3, 4])
    expect(createFrom(view)).toEqual(
      new Uint8Array(view.buffer, view.byteOffset, view.byteLength)
    )
  }),

  it('should create an empty chunk if the given input is null or undefined', () => {
    expect(createFrom(undefined)).toEqual(Uint8Array.from([]))
    expect(createFrom(null)).toEqual(Uint8Array.from([]))
  }),

  it('should create a new chunk from an array', () => {
    const bytes = [72, 105]
    expect(createFrom(bytes)).toEqual(Uint8Array.from(bytes))
  }),

  it('should create a new chunk from an iterable', () => {
    function* generateBytes() {
      yield 1
      yield 2
      yield 3
    }
    expect(createFrom(generateBytes())).toEqual(Uint8Array.from([1, 2, 3]))
  }),

  it('should create a new chunk from a string', () => {
    expect(createFrom('Hello World')).toEqual(
      Uint8Array.from([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100])
    )
  })
])
