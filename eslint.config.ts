import antfu from '@antfu/eslint-config'

export default antfu({
  ignores: ['**/coverage', '**/dist', '**/node_modules'],
  formatters: true,
  typescript: {
    tsconfigPath: 'tsconfig.json',
  },
  rules: {
    'ts/no-explicit-any': 'error',
  },
})
