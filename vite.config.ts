import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv } from 'vite';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function readPackageVersion(): string {
  try {
    const pkgPath = path.join(__dirname, 'package.json');
    const raw = fs.readFileSync(pkgPath, 'utf-8');
    const pkg = JSON.parse(raw) as { version?: string };
    const v = pkg.version?.trim();
    return v && v.length > 0 ? v : '0.0.0';
  } catch {
    return '0.0.0';
  }
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'VITE_');
  const appVersion = readPackageVersion();
  const devApiTarget = env.VITE_DEV_API_TARGET || 'http://127.0.0.1:3000';
  const base = env.VITE_BASE_PATH || '/';
  const sharedProxy = {
    target: devApiTarget,
    changeOrigin: true,
  };

  return {
    base,
    plugins: [react(), tailwindcss()],
    define: {
      'import.meta.env.VITE_APP_VERSION': JSON.stringify(appVersion),
    },
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
