import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';
const src = (p: string) => fileURLToPath(new URL(`./packages/${p}/src/index.ts`, import.meta.url));
export default defineConfig({
  resolve: {
    alias: {
      '@threatweave/core': src('core'),
      '@threatweave/ai': src('ai'),
      '@threatweave/server': src('server'),
    },
  },
  test: { include: ['packages/*/test/**/*.test.ts', 'test/**/*.test.ts'], testTimeout: 20000 },
});
