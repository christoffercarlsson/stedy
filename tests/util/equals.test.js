/* eslint-disable no-new-wrappers */
import { describe, it, expect } from '../../dist/test.js'
import { equals } from '../../dist/util.js'

export default describe('equals', () => {
  const name = 'Alice'
  return [
    it('should check for object equality', () => {
      expect(equals({ name }, { name })).toBe(true)
      expect(equals({ name }, { name: 'Bob' })).toBe(false)
      expect(equals({ name }, {})).toBe(false)
      expect(equals({}, {})).toBe(true)
    }),

    it('should check for array equality', () => {
      expect(equals([name], [name])).toBe(true)
      expect(equals([name, 'Bob'], [name, 'Bob'])).toBe(true)
      expect(equals([name], ['Bob'])).toBe(false)
      expect(equals(['Bob', name], [name, 'Bob'])).toBe(false)
      expect(equals([name], [])).toBe(false)
      expect(equals([], [])).toBe(true)
    }),

    it('should check for boolean equality', () => {
      expect(equals(true, true)).toBe(true)
      expect(equals(false, false)).toBe(true)
      expect(equals(true, false)).toBe(false)
      expect(equals(new Boolean(true), true)).toBe(false)
      expect(equals(new Boolean(false), false)).toBe(false)
      expect(equals(new Boolean(true), new Boolean(true))).toBe(true)
      expect(equals(new Boolean(false), new Boolean(false))).toBe(true)
      expect(equals(new Boolean(true), new Boolean(false))).toBe(false)
    }),

    it('should check for string equality', () => {
      expect(equals(name, name)).toBe(true)
      expect(equals(name, 'Bob')).toBe(false)
      expect(equals('', '')).toBe(true)
      expect(equals(new String(name), name)).toBe(false)
      expect(equals(new String(name), new String(name))).toBe(true)
      expect(equals(new String(name), new String('Bob'))).toBe(false)
    }),

    it('should check for numeric equality', () => {
      const n = 42
      expect(equals(n, n)).toBe(true)
      expect(equals(n, -n)).toBe(false)
      expect(equals(n, `${n}`)).toBe(false)
      expect(equals(n, 24)).toBe(false)
      expect(equals(new Number(n), n)).toBe(false)
      expect(equals(new Number(n), new Number(n))).toBe(true)
      expect(equals(new Number(n), new String(n))).toBe(false)
      expect(equals(n, BigInt(n))).toBe(false) // eslint-disable-line no-undef
      expect(equals(BigInt(n), BigInt(n))).toBe(true) // eslint-disable-line no-undef
    }),

    it('should check for date equality', () => {
      const now = new Date()
      const timestamp = 548004882233
      const then = new Date(timestamp)
      expect(equals(now, now)).toBe(true)
      expect(equals(then, then)).toBe(true)
      expect(equals(now, then)).toBe(false)
      expect(equals(then, timestamp)).toBe(false)
    }),

    it('should check for regular expression equality', () => {
      const source = '^hello$'
      const flags = 'gi'
      const r = new RegExp(source, flags)
      expect(equals(r, r)).toBe(true)
      expect(equals(r, new RegExp(source, flags))).toBe(true)
      expect(equals(r, new RegExp(source))).toBe(false)
      expect(equals(r, new RegExp('^hello', flags))).toBe(false)
      expect(equals(r, /^hello$/gi)).toBe(true)
      expect(equals(r, /^hello$/)).toBe(false)
      expect(equals(r, /^hello/gi)).toBe(false)
    }),

    it('should check for deep equality', () => {
      const age = 42
      const siblings = ['Bob', 'Charlie']
      const alice = { name, age, siblings }
      expect(equals(alice, alice)).toBe(true)
      expect(equals(alice, { siblings, age, name })).toBe(true)
      expect(equals(alice, { name: 'Dave', age: 42, siblings })).toBe(false)
      expect(
        equals(alice, { name, age, siblings: siblings.concat('Dave') })
      ).toBe(false)
    })
  ]
})
