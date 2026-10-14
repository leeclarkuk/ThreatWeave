#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { startServer, Store } from '@threatweave/server';
import { CliError, cmdCompare, cmdSchema, cmdExportTc, cmdImportTc, cmdReport, cmdScan, cmdSync, cmdValidate } from './commands.js';
import { startMcp } from './mcp.js';

const HELP = `threatweave: local-first threat modelling

Usage:
  threatweave serve [--port 4317] [--host 127.0.0.1] [--data DIR]   run the web app (data defaults to ./.threatweave-data or $THREATWEAVE_DATA)
  threatweave validate <model|.tc.json> [--json]                    check a file with the shared domain rules (exit 1 if invalid)
  threatweave compare <before> <after> [--json] [--fail-on-review]  deterministic changes and the review items they raise (exit 3 with --fail-on-review)
  threatweave import-tc <file.tc.json> [-o out.threatweave.json]    convert a Threat Composer file; prints what was lost
  threatweave export-tc <model> [-o out.tc.json]                    lossy export to Threat Composer schema 1
  threatweave report <model> [-o report.md]                         Markdown report
  threatweave scan <dir> [--json]                                   show what would be analysed; sends nothing anywhere
  threatweave sync <model> <dir> [-o out]                           deterministic source sync into a model file (no AI)
  threatweave restore <project-id> [--data DIR]                    restore a damaged project from its last good backup
  threatweave schema                                                print the JSON Schema of the native model
  threatweave mcp [--data DIR]                                      MCP server on stdio (read tools and submit_proposals only)

Exit codes: 0 ok, 1 invalid or failed, 2 usage or unreadable input, 3 review items present (compare --fail-on-review)`;

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  const { values, positionals } = parseArgs({ args: rest, allowPositionals: true, options: {
    port: { type: 'string' }, host: { type: 'string' }, data: { type: 'string' }, json: { type: 'boolean' }, output: { type: 'string', short: 'o' }, 'fail-on-review': { type: 'boolean' }, help: { type: 'boolean', short: 'h' },
  } });
  const data = resolve(values.data ?? process.env.THREATWEAVE_DATA ?? '.threatweave-data');
  if (!cmd || cmd === 'help' || cmd === '--help' || values.help) { console.log(HELP); return 0; }
  const need = (n: number, usage: string) => { if (positionals.length < n) throw new CliError(`Usage: threatweave ${usage}`, 2); };
  let res: { code: number; out: string } | undefined;
  switch (cmd) {
    case 'serve': {
      const host = values.host ?? '127.0.0.1';
      const port = Number(values.port ?? process.env.PORT ?? 4317);
      if (!Number.isInteger(port) || port < 1 || port > 65535) throw new CliError('Invalid --port', 2);
      if (host !== '127.0.0.1' && host !== 'localhost' && host !== '::1' && process.env.THREATWEAVE_BIND_ACK !== '1')
        console.warn(`WARNING: binding to ${host}. ThreatWeave has no authentication and is not a multi-user service. Anyone who can reach this port can read and change every model and use any saved API key. Prefer a localhost bind or a trusted private network.`);
      const s = await startServer({ port, host, dataDir: data });
      console.log(`ThreatWeave running at ${s.url}\nData directory: ${data}\nPress Ctrl+C to stop.`);
      return -1;
    }
    case 'mcp': await startMcp(data); return -1;
    case 'validate': need(1, 'validate <file>'); res = await cmdValidate(positionals[0]!, { json: !!values.json }); break;
    case 'compare': need(2, 'compare <before> <after>'); res = await cmdCompare(positionals[0]!, positionals[1]!, { json: !!values.json, failOnReview: !!values['fail-on-review'] }); break;
    case 'import-tc': need(1, 'import-tc <file>'); res = await cmdImportTc(positionals[0]!, values.output, { json: !!values.json }); break;
    case 'export-tc': need(1, 'export-tc <model>'); res = await cmdExportTc(positionals[0]!, values.output); break;
    case 'report': need(1, 'report <model>'); res = await cmdReport(positionals[0]!, values.output); break;
    case 'restore': need(1, 'restore <project-id>'); { const st = new Store(data); await st.restoreBackup(positionals[0]!); res = { code: 0, out: `Restored ${positionals[0]} from model.json.bak (the damaged file is kept as model.json.damaged).` }; } break;
    case 'schema': res = cmdSchema(); break;
    case 'scan': need(1, 'scan <dir>'); res = await cmdScan(positionals[0]!, { json: !!values.json }); break;
    case 'sync': need(2, 'sync <model> <dir>'); res = await cmdSync(positionals[0]!, positionals[1]!, values.output, { json: !!values.json }); break;
    default: throw new CliError(`Unknown command "${cmd}". Run threatweave --help.`, 2);
  }
  console.log(res.out);
  return res.code;
}

main().then((c) => { if (c >= 0) process.exitCode = c; }, (e) => {
  console.error(e instanceof CliError ? `error: ${e.message}` : `error: ${(e as Error).message}`);
  process.exitCode = e instanceof CliError ? e.code : (e as { issues?: unknown }).issues ? 1 : 1;
});
