import { mergeProposals, packProposalsForModel } from '@threatweave/core';
import type { Session } from './session';

/** The rule pack is pure domain logic, so it runs in the browser: works offline and is undoable. */
export function suggestFromPackClient(session: Session): string {
  let added = 0, skipped = 0;
  const ok = session.mutate('Suggest from rule pack', (m) => { const r = mergeProposals(m, packProposalsForModel(m)); added = r.added.length; skipped = r.skipped.length; return r.model; }, { immediate: true });
  if (!ok) return session.message ?? 'Failed';
  return added ? `${added} template proposal(s) added to Review${skipped ? `, ${skipped} skipped as duplicates or previously rejected` : ''}.` : `Nothing new to suggest${skipped ? ` (${skipped} already known)` : ''}.`;
}
