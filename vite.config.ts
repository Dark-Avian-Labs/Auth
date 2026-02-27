import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { fileURLToPath } from 'url';
import { defineConfig, loadEnv } from 'vite';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'VITE_');
  const devApiTarget = env.VITE_DEV_API_TARGET || 'http://127.0.0.1:3010';
  const base = env.VITE_BASE_PATH || '/';
  const sharedProxy = {
    target: devApiTarget,
    changeOrigin: true,
  };

  return {
    base,
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, 'client'),
      },
    },
    build: {
      outDir: 'dist/client',
      emptyOutDir: true,
    },
    server: {
      port: 5173,
      proxy: {
        '/api': sharedProxy,
        '/logout': sharedProxy,
      },
    },
  };
});
