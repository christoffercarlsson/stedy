import { describe, it, expect } from '../../src/test.js'
import { createFrom, toString, split } from '../../src/chunk.js'

export default describe('split', () => [
  it('should split a chunk into smaller chunks', () => {
    const views = split(createFrom('Hello'), 2)
    expect(views.map((view) => toString(view))).toEqual(['He', 'll', 'o'])
  }),

  it('should split a chunk that is smaller than the given size', () => {
    const views = split(createFrom('Hel'), 4)
    expect(views.map((view) => toString(view))).toEqual(['Hel'])
  }),

  it('should append the remainder to the last element if the chunk cannot be split evenly and appendRemainder is set to true', () => {
    const views = split(createFrom('Hello'), 2, true)
    expect(views.map((view) => toString(view))).toEqual(['He', 'llo'])
  })
])
