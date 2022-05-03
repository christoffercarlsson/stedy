import { describe, it, expect } from '../../dist/test.js'
import { partial } from '../../dist/util.js'

export default describe('partial', () => {
  const greet = (greeting, name) => `${greeting}, ${name}!`
  return [
    it('should partially apply a given function', () => {
      const sayHiTo = partial(greet, 'Hi there')
      expect(sayHiTo('Bob')).toEqual('Hi there, Bob!')
    }),

    it('should gracefully apply a function when no partials are given', () => {
      const greetPerson = partial(greet)
      expect(greetPerson('Hello', 'Alice')).toEqual('Hello, Alice!')
    })
  ]
})
