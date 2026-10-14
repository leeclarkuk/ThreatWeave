# Threat Composer fixtures

Representative `.tc.json` (schema 1) files used to test import and export. Provenance and modifications are listed in `../../NOTICE`.

| File | What it exercises |
|---|---|
| `e2e-sample.tc.json` | Minimal valid file, unmodified from the reference repository |
| `threat-composer-self-model.noimage.tc.json` | A real, larger model: 20 threats, 18 mitigations, links, STRIDE and priority metadata. Contains links to items that do not exist in the source file; the importer reports them |
| `reinforce2024-ex1.noimage.tc.json` | A workshop model with a different shape of metadata |
| `synthetic-warnings.tc.json` | Added by this project: an embedded image, an unknown top-level field and brainstorm notes |

Real Threat Composer exports often embed diagram images as base64. Those were removed from the copied examples to keep the repository small. The importer's handling of images is covered by `synthetic-warnings.tc.json`.
