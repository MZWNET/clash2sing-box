import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['src/index.ts', 'src/cli.ts'],
  format: ['es'],
  // Left unminified on purpose: this ships a CLI and a library, where readable stack
  // traces are worth more than a few kilobytes.
  minify: false,
  sourcemap: false,
})
