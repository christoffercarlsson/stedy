const alloc = (size) =>
  new Uint8Array(Number.isInteger(size) && size > 0 ? size : 0)

export default alloc
