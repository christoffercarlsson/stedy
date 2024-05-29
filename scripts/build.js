import { build } from 'esbuild'
import sourceMapPlugin from 'esbuild-plugin-exclude-vendor-source-maps'
import { globby } from 'globby'
import { exit } from 'process'

const run = async () => {
  const sharedOptions = {
    chunkNames: 'src/[hash]',
    format: 'esm',
    outbase: '.',
    outdir: 'dist',
    platform: 'browser',
    plugins: [sourceMapPlugin],
    sourcemap: true
  }
  await build({
    ...sharedOptions,
    entryPoints: ['src/index.ts'],
    bundle: true,
    splitting: true
  })
  await build({
    ...sharedOptions,
    entryPoints: ['src/index.ts'],
    bundle: true,
    format: 'cjs',
    outExtension: { '.js': '.cjs' }
  })
  await build({
    ...sharedOptions,
    entryPoints: await globby('tests/**/*.test.ts')
  })
}

run().catch((error) => {
  console.error(error)
  exit(1)
})
