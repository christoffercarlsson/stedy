import { cwd, exit } from 'process'
import { build } from '../src/build.js'

build(cwd(), [
  'src/build.js',
  'src/chunk.js',
  'src/crypto.js',
  'src/test.js',
  'src/util.js'
]).catch((error) => {
  console.error(error)
  exit(1)
})
