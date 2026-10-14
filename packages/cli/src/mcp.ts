/**
 * Narrow MCP interface over the same store and domain rules as the web app and CLI.
 *
 * Deliberately limited:
 *  - read: list projects, summarise, list review items and proposals, compare revisions, validate
 *  - write: submit PROPOSALS only. They are validated and land as pending.
 * There is no tool to accept, reject, resolve, change a status or edit the model. Those are human decisions.
 * Tool arguments and any model-produced text are treated as untrusted data.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { addIngested, ingestAiOutput, newEventId, validateModel, labelOf, type Model } from '@threatweave/core';
import { Store } from '@threatweave/server';
import { compare } from './commands.js';

const text = (t: string) => ({ content: [{ type: 'text' as const, text: t }] });
const json = (v: unknown) => text(JSON.stringify(v, null, 2));
const fail = (m: string) => ({ isError: true as const, content: [{ type: 'text' as const, text: m }] });

export async function startMcp(dataDir: string) {
  const store = new Store(dataDir);
  await store.init();
  const server = new McpServer({ name: 'threatweave', version: '0.1.0' });
  const pid = z.string().regex(/^[a-z0-9][a-z0-9-]{2,60}$/).describe('Project id from list_projects');

  server.registerTool('list_projects', { description: 'List threat model projects with counts of open review items and pending proposals.', inputSchema: {} }, async () => json(await store.list()));

  server.registerTool('get_model_summary', { description: 'Summarise a project: components, flows, boundaries, threats, assumptions, mitigations (with attested status), stale evidence, open review items.', inputSchema: { projectId: pid } }, async ({ projectId }) => {
    try {
      const { model } = await store.load(projectId);
      return json({
        id: model.id, name: model.name, demonstration: model.example,
        elements: model.elements.map((e) => ({ id: e.id, name: e.name, kind: e.kind, exposure: e.exposure })),
        flows: model.flows.map((f) => ({ id: f.id, label: labelOf(model, { type: 'flow', id: f.id }), authenticated: f.authenticated, encrypted: f.encrypted })),
        boundaries: model.boundaries.map((b) => ({ id: b.id, name: b.name, trust: b.trust, members: b.memberIds })),
        threats: model.threats.map((t) => ({ id: t.id, title: t.title, status: t.status, basis: t.basis, evidenceStrength: t.evidenceStrength, targets: t.targets })),
        mitigations: model.mitigations.map((m) => ({ id: m.id, title: m.title, status: m.status, attestedBy: m.statusSetBy?.actor ?? null, threats: m.threatIds })),
        staleEvidence: model.evidence.filter((e) => e.stale).map((e) => ({ id: e.id, summary: e.summary, reason: e.staleReason })),
        openReviewItems: model.reviewItems.filter((r) => r.status === 'open').length, pendingProposals: model.proposals.filter((p) => p.status === 'pending').length,
      });
    } catch (e) { return fail((e as Error).message); }
  });

  server.registerTool('validate_model', { description: 'Validate a stored project with the shared domain rules.', inputSchema: { projectId: pid } }, async ({ projectId }) => {
    try { const { model } = await store.load(projectId); const v = validateModel(model); return json({ ok: v.ok, issues: v.issues }); } catch (e) { return fail((e as Error).message); }
  });

  server.registerTool('list_review_items', { description: 'List review items (what needs a human look after a change) with the relationship trace explaining each.', inputSchema: { projectId: pid, status: z.enum(['open', 'resolved', 'dismissed', 'all']).default('open') } }, async ({ projectId, status }) => {
    try { const { model } = await store.load(projectId); return json(model.reviewItems.filter((r) => status === 'all' || r.status === status).map((r) => ({ id: r.id, status: r.status, target: { ...r.target, label: labelOf(model, r.target) }, reason: r.reason, trace: r.trace, deterministic: r.deterministic }))); } catch (e) { return fail((e as Error).message); }
  });

  server.registerTool('list_proposals', { description: 'List proposals by status. Proposals are suggestions; only a person can accept them.', inputSchema: { projectId: pid, status: z.enum(['pending', 'accepted', 'rejected', 'all']).default('pending') } }, async ({ projectId, status }) => {
    try { const { model } = await store.load(projectId); return json(model.proposals.filter((p) => status === 'all' || p.status === status).map((p) => ({ id: p.id, key: p.key, origin: p.origin, status: p.status, basis: p.basis, payload: p.payload, reasoning: p.reasoning, validationNotes: p.validationNotes }))); } catch (e) { return fail((e as Error).message); }
  });

  server.registerTool('compare_models', { description: 'Compare two saved revisions of a project (or "current"), returning deterministic changes and the review items they would raise. Not an exhaustive impact analysis.', inputSchema: { projectId: pid, from: z.string().describe('Revision id or "current"'), to: z.string().default('current') } }, async ({ projectId, from, to }) => {
    try {
      const get = async (r: string): Promise<Model> => (r === 'current' ? (await store.load(projectId)).model : store.revision(projectId, r));
      const c = compare(await get(from), await get(to));
      return json({ changes: c.changes, reviewItems: c.reviewItems });
    } catch (e) { return fail((e as Error).message); }
  });

  server.registerTool('list_revisions', { description: 'List saved revisions of a project for comparison.', inputSchema: { projectId: pid } }, async ({ projectId }) => { try { return json(await store.revisions(projectId)); } catch (e) { return fail((e as Error).message); } });

  server.registerTool('submit_proposals', {
    description: 'Submit structured proposals (threats, mitigations, assumptions, questions, components, flows, boundaries, assets) for human review. Each is validated against the model; invalid or ungrounded items are discarded with reasons. File evidence cannot be asserted through MCP, so proposals arrive as hypotheses. Nothing is accepted automatically and mitigations can never be marked implemented or verified.',
    inputSchema: { projectId: pid, summary: z.string().max(2000).default(''), proposals: z.array(z.unknown()).max(40) },
  }, async ({ projectId, summary, proposals }) => {
    try {
      let out: { added: number; discarded: Array<{ index: number; reason: string }>; skipped: Array<{ title: string; reason: string }> } = { added: 0, discarded: [], skipped: [] };
      await store.update(projectId, (m) => {
        const ing = ingestAiOutput(m, { summary, proposals }, { runId: newEventId('run'), files: new Map(), origin: 'mcp' });
        const add = addIngested(m, ing);
        out = { added: add.added.length, discarded: ing.discarded, skipped: add.skipped };
        return add.model;
      });
      return json({ ...out, note: 'Added proposals are pending. A person accepts, edits or rejects them in the web app.' });
    } catch (e) { return fail((e as Error).message); }
  });

  await server.connect(new StdioServerTransport());
}
