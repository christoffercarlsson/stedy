const getMessage = (message, actual, expected, operator) => {
  if (typeof message === 'string') {
    return [message, false]
  }
  return ['', true]
}

export default class AssertionError extends Error {
  constructor({ message, actual, expected, operator, params } = {}) {
    const [msg, generatedMessage] = getMessage(
      message,
      actual,
      expected,
      operator
    )
    super(msg)
    this.actual = actual
    this.expected = expected
    this.generatedMessage = generatedMessage
    this.operator = operator
    this.params = params
  }
}
