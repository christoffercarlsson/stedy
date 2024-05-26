import { createFrom } from '../../src'

describe('split', () => {
  it('should split a chunk into smaller chunks', () => {
    const views = createFrom('Hello').split(2, false)
    expect(views.map((view) => view.toString())).toEqual(['He', 'll', 'o'])
  })

  it('should split a chunk that is smaller than the given size', () => {
    const views = createFrom('Hel').split(4)
    expect(views.map((view) => view.toString())).toEqual(['Hel'])
  })

  it('should append the remainder to the last element if the chunk cannot be split evenly and appendRemainder is set to true', () => {
    const views = createFrom('Hello').split(2, true)
    expect(views.map((view) => view.toString())).toEqual(['He', 'llo'])
  })
})
