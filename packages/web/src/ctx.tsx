import { createContext, useContext } from 'react';
import type { Model, Ref } from '@threatweave/core';
import type { Session } from './session';

export type SelType = Ref['type'] | 'proposal' | 'review' | 'run' | 'source';
export interface Sel { type: SelType; id: string }
export interface WorkspaceApi {
  session: Session;
  model: Model;
  actor: string;
  selection: Sel | null;
  select: (s: Sel | null) => void;
  go: (tab: string) => void;
  tab: string;
  /** Open an entity: navigates to the tab that owns it and selects it. */
  open: (s: Sel) => void;
  refreshExamples: number;
}
export const WorkspaceCtx = createContext<WorkspaceApi | null>(null);
export const useWs = () => { const c = useContext(WorkspaceCtx); if (!c) throw new Error('no workspace'); return c; };

export const TAB_OF: Record<string, string> = {
  element: 'architecture', flow: 'architecture', boundary: 'architecture', asset: 'architecture', threat: 'threats', assumption: 'assumptions',
  mitigation: 'mitigations', evidence: 'evidence', source: 'evidence', proposal: 'review', review: 'review', run: 'source', system: 'architecture',
};

/** Which diagram elements a selection should light up. */
export function highlightFor(model: Model, sel: Sel | null): { elements: Set<string>; flows: Set<string>; boundaries: Set<string> } {
  const out = { elements: new Set<string>(), flows: new Set<string>(), boundaries: new Set<string>() };
  if (!sel) return out;
  const addRef = (r: { type: string; id: string }) => {
    if (r.type === 'element') out.elements.add(r.id);
    else if (r.type === 'flow') { out.flows.add(r.id); const f = model.flows.find((x) => x.id === r.id); if (f) { out.elements.add(f.from); out.elements.add(f.to); } }
    else if (r.type === 'boundary') { out.boundaries.add(r.id); }
    else if (r.type === 'asset') model.assets.find((a) => a.id === r.id)?.storedIn.forEach((e) => out.elements.add(e));
  };
  switch (sel.type) {
    case 'element': {
      out.elements.add(sel.id);
      model.flows.filter((f) => f.from === sel.id || f.to === sel.id).forEach((f) => out.flows.add(f.id));
      model.boundaries.filter((b) => b.memberIds.includes(sel.id)).forEach((b) => out.boundaries.add(b.id));
      break;
    }
    case 'flow': case 'boundary': case 'asset': addRef(sel); break;
    case 'threat': model.threats.find((t) => t.id === sel.id)?.targets.forEach(addRef); break;
    case 'assumption': model.assumptions.find((a) => a.id === sel.id)?.relatesTo.forEach(addRef); break;
    case 'mitigation': model.mitigations.find((m) => m.id === sel.id)?.threatIds.forEach((t) => model.threats.find((x) => x.id === t)?.targets.forEach(addRef)); break;
    case 'review': { const r = model.reviewItems.find((x) => x.id === sel.id); if (r) { addRef(r.target); if (r.target.type === 'threat') model.threats.find((t) => t.id === r.target.id)?.targets.forEach(addRef); if (r.target.type === 'assumption') model.assumptions.find((a) => a.id === r.target.id)?.relatesTo.forEach(addRef); if (r.target.type === 'mitigation') model.mitigations.find((m) => m.id === r.target.id)?.threatIds.forEach((t) => model.threats.find((x) => x.id === t)?.targets.forEach(addRef)); } break; }
    case 'proposal': {
      const p = model.proposals.find((x) => x.id === sel.id)?.payload;
      if (p?.kind === 'add-threat') p.targets.forEach((t) => addRef({ type: t.type, id: t.ref }));
      if (p?.kind === 'add-flow') { out.elements.add(p.from); out.elements.add(p.to); }
      break;
    }
    default: break;
  }
  return out;
}
