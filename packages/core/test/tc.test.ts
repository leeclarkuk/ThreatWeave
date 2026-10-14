import { readFileSync, readdirSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { exportThreatComposer, importThreatComposer, serialiseModel, validateModel, Model } from '../src/index.js';

const fx = (n: string) => JSON.parse(readFileSync(new URL(`../../../fixtures/tc/${n}`, import.meta.url), 'utf8'));
const schema = JSON.parse(readFileSync(new URL('../../../third_party/threat-composer-v1.schema.json', import.meta.url), 'utf8'));
const ajv = new Ajv2020({ strict: false, allErrors: true });
addFormats(ajv);
ajv.addFormat('starts_with', true);
const validateTc = ajv.compile(schema);

describe('threat composer fixtures are valid per the inspected schema', () => {
  for (const f of readdirSync(new URL('../../../fixtures/tc/', import.meta.url)).filter((x) => x.endsWith('.tc.json'))) {
    it(f, () => {
      const ok = f.startsWith('synthetic') ? true : validateTc(fx(f));
      expect(ok, JSON.stringify(validateTc.errors?.slice(0, 3))).toBe(true);
    });
  }
});

describe('import', () => {
  it('imports the self-model with stable ids and a valid native model', () => {
    const tc = fx('threat-composer-self-model.noimage.tc.json');
    const { model, warnings, stats } = importThreatComposer(tc);
    const v = validateModel(model);
    expect(v.issues.filter((i) => i.severity === 'error')).toEqual([]);
    expect(stats.threats).toBe(tc.threats.length);
    expect(stats.mitigations).toBe(tc.mitigations.length);
    // ids preserved (lower-cased uuid under a type prefix)
    expect(model.threats.map((t) => t.id)).toContain(`thr_${tc.threats[0].id}`);
    // links preserved
    // The reference example itself contains links to threats that do not exist; those are skipped and reported.
    const threatIds = new Set(tc.threats.map((t: any) => t.id)), mitIds = new Set(tc.mitigations.map((m: any) => m.id));
    const valid = tc.mitigationLinks.filter((l: any) => threatIds.has(l.linkedId) && mitIds.has(l.mitigationId));
    const dangling = tc.mitigationLinks.length - valid.length;
    expect(dangling).toBeGreaterThan(0);
    const linked = model.mitigations.reduce((n, m) => n + m.threatIds.length, 0);
    expect(linked).toBe(valid.length);
    const asmIds = new Set(tc.assumptions.map((a: any) => a.id));
    const badAsm = tc.assumptionLinks.filter((l: any) => !asmIds.has(l.assumptionId) || !(l.type === 'Threat' ? threatIds : mitIds).has(l.linkedId)).length;
    expect(warnings.find((w) => w.code === 'dangling-link')?.count).toBe(dangling + badAsm);
    expect(warnings.find((w) => w.code === 'architecture-as-text')).toBeTruthy();
    // statuses map, resolved != verified
    expect(model.mitigations.some((m) => m.status === 'verified')).toBe(false);
  });
  it('reports unsupported content visibly', () => {
    const { warnings } = importThreatComposer(fx('synthetic-warnings.tc.json'));
    const codes = warnings.map((w) => w.code);
    expect(codes).toContain('diagram-image-dropped');
    expect(codes).toContain('unknown-top-level');
    expect(codes).toContain('brainstorm-dropped');
  });
  it('rejects non-TC input and unknown schema versions', () => {
    expect(() => importThreatComposer([])).toThrow();
    expect(() => importThreatComposer({ schema: 2 })).toThrow(/schema version/);
  });
});

describe('export is valid TC, and honest about loss', () => {
  it('produces schema-valid output and warns on lossy fields', () => {
    const { model } = importThreatComposer(fx('threat-composer-self-model.noimage.tc.json'));
    const { json, warnings } = exportThreatComposer(model);
    expect(validateTc(json), JSON.stringify(validateTc.errors?.slice(0, 3))).toBe(true);
    expect(warnings.some((w) => w.code === 'judgements-dropped')).toBe(true);
  });
  it('preserves supported information on a TC to native to TC round trip', () => {
    const tc = fx('threat-composer-self-model.noimage.tc.json');
    const { json } = exportThreatComposer(importThreatComposer(tc).model);
    expect(json.threats.map((t: any) => t.id).sort()).toEqual(tc.threats.map((t: any) => t.id).sort());
    const byId = (xs: any[]) => Object.fromEntries(xs.map((x) => [x.id, x]));
    const a = byId(tc.threats), b = byId(json.threats);
    for (const id of Object.keys(a)) {
      for (const k of ['threatSource', 'prerequisites', 'threatAction', 'threatImpact', 'status'] as const)
        expect(b[id][k] ?? '', `${id}.${k}`).toEqual(a[id][k] ?? '');
    }
    const ids = new Set(tc.threats.map((t: any) => t.id));
    expect(json.mitigationLinks.length).toBe(tc.mitigationLinks.filter((l: any) => ids.has(l.linkedId)).length);
  });
});

describe('deterministic serialisation', () => {
  it('is byte-stable across parse/serialise and key-order independent', () => {
    const { model } = importThreatComposer(fx('e2e-sample.tc.json'));
    const once = serialiseModel(Model.parse(model));
    const shuffled = JSON.parse(once);
    shuffled.threats.reverse();
    const twice = serialiseModel(Model.parse(shuffled));
    expect(twice).toBe(once);
    expect(once.endsWith('\n')).toBe(true);
  });
});
