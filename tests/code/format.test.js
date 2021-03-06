import { describe, it, expect } from '../../dist/test.js'
import { format } from '../../dist/code.js'

export default describe('format', () => [
  it('should format JavaScript according to formatting rules', async () => {
    const result = await format('javascript', 'const foo = "bar";')
    expect(result).toEqual("const foo = 'bar'\n")
  }),

  it('should format CSS according to formatting rules', async () => {
    const result = await format('css', 'body { margin: 0; }')
    expect(result).toEqual('body {\n  margin: 0;\n}\n')
  }),

  it('should format JSON according to formatting rules', async () => {
    const result = await format('json', '{"person": "Alice"}')
    expect(result).toEqual('{\n  "person": "Alice"\n}\n')
  }),

  it('should format HTML according to formatting rules', async () => {
    const result = await format('html', '<p>Hello</p>')
    expect(result).toEqual('<p>Hello</p>\n')
  }),

  it('should format Markdowm according to formatting rules', async () => {
    const result = await format('markdown', '# Hello World')
    expect(result).toEqual('# Hello World\n')
  })
])
