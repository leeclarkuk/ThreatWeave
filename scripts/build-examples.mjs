// Regenerates examples/northwind.threatweave.json from examples/repos/northwind-v1 (deterministic apart from timestamps).
import { writeFileSync } from 'node:fs';
import { buildNorthwindExample, serialiseModel, validateModel } from '@threatweave/core';
import { scanDirectory, loadSelected, snapshotRevision } from '@threatweave/server';

const scan = await scanDirectory(new URL('../examples/repos/northwind-v1', import.meta.url).pathname);
const { inputs } = await loadSelected(scan);
const model = buildNorthwindExample(inputs, snapshotRevision(inputs));
const v = validateModel(model);
if (!v.ok) { console.error(v.issues); process.exit(1); }
writeFileSync(new URL('../examples/northwind.threatweave.json', import.meta.url), serialiseModel(v.model));
console.log(`wrote examples/northwind.threatweave.json (${model.elements.length} components, ${model.threats.length} threats)`);
