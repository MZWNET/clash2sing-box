import antfu from "@antfu/eslint-config";
import oxlint from "eslint-plugin-oxlint";

export default antfu({
  ignores: ["**/coverage", "**/dist", "**/node_modules"],
  formatters: true,
  typescript: {
    tsconfigPath: "tsconfig.json",
  },
  stylistic: false,
  rules: {
    "ts/no-explicit-any": "error",
    "jsonc/sort-keys": "off",
    ...oxlint.configs.recommended.rules,
  },
});
