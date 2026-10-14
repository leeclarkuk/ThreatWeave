// Regenerates examples/northwind.threatweave.json from examples/repos/northwind-v1.
// Deterministic: fixed clock and seeded ids, so the output is byte-identical on every run and a test can assert the
// committed file is up to date. (Run via `npm run examples`; run as a module by test/examples.test.ts.)
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { buildNorthwindExample, serialiseModel, useFixedClock, useSeededRandom, validateModel } from '@threatweave/core';
import { scanDirectory, loadSelected, snapshotRevision } from '@threatweave/server';

export const EXAMPLE_PATH = fileURLToPath(new URL('../examples/northwind.threatweave.json', import.meta.url));

export async function buildExampleText() {
  useFixedClock('2026-01-01T00:00:00Z');
  useSeededRandom(20260101);
  try {
    const scan = await scanDirectory(fileURLToPath(new URL('../examples/repos/northwind-v1', import.meta.url)));
    const { inputs } = await loadSelected(scan);
    const model = buildNorthwindExample(inputs, snapshotRevision(inputs));
    const v = validateModel(model);
    if (!v.ok || !v.model) throw new Error(`example invalid: ${JSON.stringify(v.issues.slice(0, 3))}`);
    return serialiseModel(v.model);
  } finally { useFixedClock(null); useSeededRandom(null); }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  writeFileSync(EXAMPLE_PATH, await buildExampleText());
  console.log('wrote examples/northwind.threatweave.json');
}
