import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: 'src/index.ts',
  format: ['es'],
  minify: true,
  sourcemap: false,
})
