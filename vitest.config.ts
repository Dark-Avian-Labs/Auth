import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['**/*.test.{ts,tsx}'],
    setupFiles: ['server/test/setupEnv.ts'],
    env: {
      MOCK_DB: process.env.MOCK_DB ?? 'true',
      SESSION_SECRET: process.env.SESSION_SECRET ?? 'auth-dev-only-session-secret-32char',
    },
  },
});
