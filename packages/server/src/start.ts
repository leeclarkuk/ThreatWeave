import { serve } from '@hono/node-server';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve, sep, delimiter } from 'node:path';
import { createApp } from './app.js';

export interface StartOptions { port: number; host: string; dataDir: string }

export function defaultPaths() {
  const here = fileURLToPath(new URL('.', import.meta.url));
  const cands = (p: string) => [resolve(here, '../../../', p), resolve(here, '../../', p), resolve(process.cwd(), p)];
  const find = (p: string, marker: string) => cands(p).find((x) => existsSync(resolve(x, marker)));
  return { webDir: process.env.THREATWEAVE_WEB_DIR ?? find('packages/web/dist', 'index.html') ?? find('web', 'index.html'), examplesDir: process.env.THREATWEAVE_EXAMPLES ?? find('examples', 'repos') };
}

export async function startServer(o: StartOptions) {
  const { webDir, examplesDir } = defaultPaths();
  const allowedRoots = (process.env.THREATWEAVE_SOURCE_ROOTS ?? '').split(delimiter).filter(Boolean).map((p) => resolve(p));
  const extraHosts = (process.env.THREATWEAVE_ALLOWED_HOSTS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const { app } = await createApp({ dataDir: o.dataDir, webDir, examplesDir, allowedRoots, allowedHosts: extraHosts });
  return new Promise<{ close: () => void; url: string }>((res) => {
    const server = serve({ fetch: app.fetch, port: o.port, hostname: o.host }, (info) => res({ url: `http://${o.host === '0.0.0.0' ? 'localhost' : o.host}:${info.port}`, close: () => server.close() }));
  });
}
void sep;
