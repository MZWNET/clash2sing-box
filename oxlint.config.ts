import oxlint from '@mzwing/oxc-config'

const config = oxlint({
  type: 'lib',
  typescript: true,
})

export default {
  ...config,
  overrides: [
    ...(config.overrides ?? []),
    {
      // The shared config waives this rule for CLI entries, but recognises them by name
      // (`cli.ts`, `cli/`). This package's entry is `src/index.ts` so that it matches the
      // `dist/index.mjs` it builds to, which the glob misses. Top-level await is safe here
      // for the reason the rule exists: the file is a bin entry that nothing imports.
      files: ['src/index.ts'],
      rules: { 'antfu/no-top-level-await': 'off' },
    },
  ],
}
