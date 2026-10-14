import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { validateModel } from '@threatweave/core';

describe('bundled example', () => {
  it('is up to date: regenerating it produces byte-identical output', async () => {
    // @ts-expect-error plain ES module script without types
    const { buildExampleText, EXAMPLE_PATH } = await import('../../../scripts/build-examples.mjs');
    const regenerated: string = await buildExampleText();
    const committed = readFileSync(EXAMPLE_PATH, 'utf8');
    expect(regenerated === committed, 'run `npm run build && npm run examples` and commit the result').toBe(true);
    expect(validateModel(JSON.parse(committed)).ok).toBe(true);
  });
});
