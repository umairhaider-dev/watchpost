/// <reference types="vitest/config" />
import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv } from 'vite';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const apiTarget = env.VITE_API_PROXY_TARGET ?? 'http://localhost:8000';

  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        // In development the API runs separately; proxying keeps requests same-origin.
        '/api': { target: apiTarget, changeOrigin: true },
      },
    },
    build: {
      sourcemap: true,
    },
    test: {
      environment: 'jsdom',
      setupFiles: ['./src/test/setup.ts'],
      restoreMocks: true,
      css: false,
      // Room for the longer async waits configured in src/test/setup.ts.
      testTimeout: 15_000,
    },
  };
});
