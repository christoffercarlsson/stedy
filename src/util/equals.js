const getClassName = (object) => Object.prototype.toString.call(object)

const getKeys = (object) => {
  const names = Object.getOwnPropertyNames(object)
  if (object instanceof Error && object.stack) {
    return names.filter((name) => name !== 'stack')
  }
  return names
}

const isPrimitive = (value) => value === null || typeof value !== 'object'

const isPrimitiveWrapper = (className) =>
  [
    '[object Boolean]',
    '[object String]',
    '[object Number]',
    '[object BigInt]',
    '[object Symbol]',
    '[object Date]'
  ].includes(className)

const equals = (a, b) => {
  if (isPrimitive(a) || isPrimitive(b)) {
    return a === b
  }
  const className = getClassName(a)
  if (className !== getClassName(b)) {
    return false
  }
  if (isPrimitiveWrapper(className)) {
    return a.valueOf() === b.valueOf()
  }
  if (className === '[object RegExp]') {
    return a.source === b.source && a.flags === b.flags
  }
  const keys = getKeys(a)
  if (keys.length !== getKeys(b).length) {
    return false
  }
  return keys.every((key) => equals(a[key], b[key]))
}

export default equals
