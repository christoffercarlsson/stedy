import toMatch from './to-match.js'

const toThrow = (received, expected) => {
  try {
    received()
    return false
  } catch (error) {
    return toMatch(error.message || '', expected)
  }
}

export default toThrow
