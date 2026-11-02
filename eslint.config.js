import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['dist', 'coverage', 'src-tauri', 'node_modules'] },
  {
    files: ['**/*.{ts,tsx}'],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2023,
      globals: { ...globals.browser },
    },
    plugins: {
      'react-hooks': reactHooks,
    },
    rules: {
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
    },
  },
  // Styling policy for first-party code only; src/components/ui is vendored
  // shadcn registry output and is kept as generated.
  {
    files: ['src/**/*.{ts,tsx}'],
    ignores: ['src/components/ui/**'],
    plugins: {
      'react-refresh': reactRefresh,
    },
    rules: {
      'react-refresh/only-export-components': [
        'warn',
        { allowConstantExport: true },
      ],
      'no-restricted-syntax': [
        'error',
        {
          selector: "JSXAttribute[name.name='style']",
          message:
            'Inline style props are not allowed. Use Tailwind utility classes and the design tokens in src/styles/globals.css.',
        },
        {
          selector:
            "JSXAttribute[name.name='className'] Literal[value=/-\\[(#|oklch|rgb|hsl)/]",
          message:
            'Tailwind arbitrary color values are not allowed. Use a design token from src/styles/globals.css (e.g. bg-background, text-muted-foreground).',
        },
        {
          selector:
            "JSXAttribute[name.name='className'] TemplateElement[value.raw=/-\\[(#|oklch|rgb|hsl)/]",
          message:
            'Tailwind arbitrary color values are not allowed. Use a design token from src/styles/globals.css (e.g. bg-background, text-muted-foreground).',
        },
        {
          selector: "JSXAttribute[name.name='className'] Literal[value=/!/]",
          message:
            'The !important modifier is not allowed in className. Rely on utility order or design tokens from src/styles/globals.css.',
        },
        {
          selector:
            "JSXAttribute[name.name='className'] TemplateElement[value.raw=/!/]",
          message:
            'The !important modifier is not allowed in className. Rely on utility order or design tokens from src/styles/globals.css.',
        },
      ],
    },
  },
)
