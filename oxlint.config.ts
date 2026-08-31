import { createOxlintConfig } from '@d3lm/lint-preset/oxlint';
import { defineConfig } from 'oxlint';

export default defineConfig({
  extends: [createOxlintConfig()],
  overrides: [
    {
      files: ['**/*.{ts,tsx,mts,cts}'],
      rules: {
        'unicorn/no-process-exit': 'off',
        'typescript/no-floating-promises': 'off',
      },
    },
  ],
});
