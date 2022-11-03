import toBe from './to-be.js'

const toBeDefined = (received) => !toBe(received, undefined)

export default toBeDefined
