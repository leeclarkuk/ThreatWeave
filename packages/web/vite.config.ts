import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { '@threatweave/core': fileURLToPath(new URL('../core/src/index.ts', import.meta.url)) } },
  server: { port: 5173, proxy: { '/api': { target: 'http://127.0.0.1:4317', changeOrigin: false, headers: { host: 'localhost:4317' } } } },
  build: { outDir: 'dist', sourcemap: false, chunkSizeWarningLimit: 900 },
});
