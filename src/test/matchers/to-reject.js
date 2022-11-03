import toMatch from './to-match.js'

const toReject = async (received, expected) => {
  try {
    await received
    return false
  } catch (error) {
    return toMatch(error.message || '', expected)
  }
}

export default toReject
