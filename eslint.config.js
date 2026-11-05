import js from '@eslint/js'
import jest from 'eslint-plugin-jest'
import prettierRecommended from 'eslint-plugin-prettier/recommended'
import { defineConfig } from 'eslint/config'
import globals from 'globals'
import ts from 'typescript-eslint'

export default defineConfig(js.configs.recommended, ts.configs.recommended, prettierRecommended, {
  plugins: { jest },
  languageOptions: {
    globals: { ...globals.node, ...globals.jest },
  },
})
