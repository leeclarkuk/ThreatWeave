import { createServer, type IncomingMessage, type ServerResponse, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface Seen { url: string; headers: IncomingMessage['headers']; body: any }
export type Handler = (req: Seen, res: ServerResponse) => void | Promise<void>;

/** Controlled fixture server. Responses follow the documented shapes of each API; this is a SIMULATION, not a live endpoint. */
export async function startMock(handlers: Handler[]): Promise<{ url: string; seen: Seen[]; close: () => Promise<void>; server: Server }> {
  const seen: Seen[] = [];
  let i = 0;
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      let body: any = {};
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* keep {} */ }
      const s = { url: req.url ?? '', headers: req.headers, body };
      seen.push(s);
      const h = handlers[Math.min(i++, handlers.length - 1)]!;
      await h(s, res);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  return { url: `http://127.0.0.1:${port}`, seen, server, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }) };
}

export const json = (res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) => {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
};

export const anthropicOk = (text: string, usage = { input_tokens: 1200, output_tokens: 340 }, stop = 'end_turn'): Handler => (_r, res) =>
  json(res, 200, { id: 'msg_sim', type: 'message', role: 'assistant', model: 'sim-model', content: [{ type: 'text', text }], stop_reason: stop, stop_sequence: null, usage });

export const openaiOk = (text: string, usage?: object, finish = 'stop'): Handler => (_r, res) =>
  json(res, 200, { id: 'chatcmpl-sim', object: 'chat.completion', model: 'sim-model', choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: finish }], ...(usage ? { usage } : {}) });
