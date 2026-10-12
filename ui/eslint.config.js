import js from "@eslint/js"
import globals from "globals"
import tseslint from "typescript-eslint"

export default tseslint.config(
  { ignores: ["dist", "src/api/schema.d.ts"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  { files: ["**/*.{ts,tsx}"], languageOptions: { globals: globals.browser } },
  { files: ["*.{js,ts}", "dev/**/*.ts"], languageOptions: { globals: globals.node } },
)
