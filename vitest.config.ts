import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['server/**/*.test.ts', 'client/**/*.test.ts'],
    setupFiles: ['server/test/setupEnv.ts'],
    env: {
      MOCK_DB: process.env.MOCK_DB ?? 'true',
    },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      reportsDirectory: 'coverage',
    },
  },
});
