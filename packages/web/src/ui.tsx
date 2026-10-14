import { createContext, useCallback, useContext, useEffect, useId, useRef, useState, type ReactNode } from 'react';
import type { Model, Ref, RefType, MitigationStatus } from '@threatweave/core';
import { labelOf } from '@threatweave/core';

/* ---------------- marks (glyph + word) ---------------- */
export const Mark = ({ kind = 'plain', children, title, dashed }: { kind?: 'review' | 'ok' | 'stale' | 'danger' | 'info' | 'plain'; children: ReactNode; title?: string; dashed?: boolean }) => (
  <span className={`mark ${kind}${dashed ? ' dashed' : ''}`} title={title}>{children}</span>
);

export const ReviewMark = ({ n }: { n?: number }) => <Mark kind="review" title="Open review items reference this">◆ Needs review{n && n > 1 ? ` ×${n}` : ''}</Mark>;
export const StaleMark = ({ reason }: { reason?: string | undefined }) => <Mark kind="stale" title={reason}>▲ Stale evidence</Mark>;

export const MIT_STATUS: Record<MitigationStatus, { glyph: string; label: string; kind: 'plain' | 'info' | 'ok' | 'review' }> = {
  proposed: { glyph: '◇', label: 'Proposed', kind: 'plain' },
  planned: { glyph: '○', label: 'Planned', kind: 'plain' },
  'in-progress': { glyph: '◐', label: 'In progress', kind: 'info' },
  implemented: { glyph: '●', label: 'Implemented (not verified)', kind: 'info' },
  verified: { glyph: '✓', label: 'Verified', kind: 'ok' },
  'wont-do': { glyph: '⊘', label: "Won't do", kind: 'plain' },
};
export function MitigationMark({ status, staleVerification }: { status: MitigationStatus; staleVerification?: boolean }) {
  if (status === 'verified' && staleVerification) return <Mark kind="stale">▲ Verified, evidence stale</Mark>;
  const s = MIT_STATUS[status];
  return <Mark kind={s.kind}>{s.glyph} {s.label}</Mark>;
}
export const BasisMark = ({ basis }: { basis: 'observed' | 'inferred' | 'hypothesis' }) => (
  <Mark kind={basis === 'hypothesis' ? 'plain' : 'info'} dashed={basis === 'hypothesis'} title={{ observed: 'Read directly from a source or stated as fact', inferred: 'Reasoned from observed facts', hypothesis: 'Plausible; awaiting validation' }[basis]}>
    {{ observed: '◉ Observed', inferred: '∴ Inferred', hypothesis: '? Hypothesis' }[basis]}
  </Mark>
);
export const OriginMark = ({ origin, actor }: { origin: string; actor?: string | undefined }) => (
  <Mark kind={origin === 'human' ? 'plain' : 'info'} title={actor ? `by ${actor}` : undefined}>{{ human: 'Person', ai: 'AI draft', 'pack-rule': 'Rule pack', import: 'Import', 'source-scan': 'Source scan', mcp: 'MCP client' }[origin] ?? origin}{origin === 'human' && actor ? `: ${actor}` : ''}</Mark>
);
export const STRENGTH_GLYPH = { none: '▁▁▁ none', weak: '▃▁▁ weak', moderate: '▃▅▁ moderate', strong: '▃▅▇ strong' } as const;
export const LEVEL_TEXT = { unknown: 'not assessed', low: 'low', medium: 'medium', high: 'high' } as const;

/* ---------------- fields ---------------- */
interface FieldProps { label: string; value: string; onCommit: (v: string) => void; multiline?: boolean; hint?: string; placeholder?: string; rows?: number; mono?: boolean; required?: boolean; /** Report every keystroke. Use whenever a button elsewhere depends on this value, so Tab never skips a disabled button. */ live?: boolean }
/** Commit-on-blur text field, so one edit is one undo step. */
export function TextField({ label, value, onCommit, multiline, hint, placeholder, rows, mono, required, live }: FieldProps) {
  const [draft, setDraft] = useState(value);
  const id = useId();
  useEffect(() => setDraft(value), [value]);
  const commit = () => { if (draft !== value) onCommit(draft); };
  const common = { id, value: draft, placeholder, required, 'aria-required': required, className: mono ? 'mono' : undefined, onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => { setDraft(e.target.value); if (live) onCommit(e.target.value); }, onBlur: commit };
  return (
    <div className="field">
      <label className="lbl" htmlFor={id}>{label}{required ? ' *' : ''}</label>
      {multiline ? <textarea {...common} rows={rows ?? 3} /> : <input {...common} onKeyDown={(e) => { if (e.key === 'Enter') commit(); }} />}
      {hint && <span className="hint">{hint}</span>}
    </div>
  );
}

export function SelectField<T extends string>({ label, value, options, onChange, hint, disabled }: { label: string; value: T; options: Array<{ value: T; label: string }>; onChange: (v: T) => void; hint?: string; disabled?: boolean }) {
  const id = useId();
  return (
    <div className="field">
      <label className="lbl" htmlFor={id}>{label}</label>
      <select id={id} value={value} disabled={disabled} onChange={(e) => onChange(e.target.value as T)}>
        {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
      {hint && <span className="hint">{hint}</span>}
    </div>
  );
}

export function ListField({ label, value, onCommit, hint }: { label: string; value: string[]; onCommit: (v: string[]) => void; hint?: string }) {
  return <TextField label={label} multiline rows={3} value={value.join('\n')} hint={hint ?? 'One per line'} onCommit={(v) => onCommit(v.split('\n').map((s) => s.trim()).filter(Boolean))} />;
}

/* ---------------- entity pickers ---------------- */
export const REF_TYPES: Array<{ type: RefType; plural: string }> = [
  { type: 'element', plural: 'Components' }, { type: 'flow', plural: 'Data flows' }, { type: 'boundary', plural: 'Trust boundaries' }, { type: 'asset', plural: 'Assets' },
];
export function candidates(model: Model, types: RefType[] = ['element', 'flow', 'boundary', 'asset']): Ref[] {
  const out: Ref[] = [];
  if (types.includes('element')) out.push(...model.elements.map((e) => ({ type: 'element' as const, id: e.id })));
  if (types.includes('flow')) out.push(...model.flows.map((e) => ({ type: 'flow' as const, id: e.id })));
  if (types.includes('boundary')) out.push(...model.boundaries.map((e) => ({ type: 'boundary' as const, id: e.id })));
  if (types.includes('asset')) out.push(...model.assets.map((e) => ({ type: 'asset' as const, id: e.id })));
  if (types.includes('threat')) out.push(...model.threats.map((e) => ({ type: 'threat' as const, id: e.id })));
  if (types.includes('mitigation')) out.push(...model.mitigations.map((e) => ({ type: 'mitigation' as const, id: e.id })));
  return out;
}
export function RefPicker({ model, label, value, onChange, types, onOpen }: { model: Model; label: string; value: Ref[]; onChange: (v: Ref[]) => void; types?: RefType[]; onOpen?: (r: Ref) => void }) {
  const id = useId();
  const all = candidates(model, types);
  const free = all.filter((c) => !value.some((v) => v.type === c.type && v.id === c.id));
  const typeLabel = (t: string) => ({ element: 'Component', flow: 'Flow', boundary: 'Boundary', asset: 'Asset', threat: 'Threat', mitigation: 'Mitigation' }[t] ?? t);
  return (
    <div className="field">
      <span className="lbl" id={`${id}-l`}>{label}</span>
      <div className="chips" role="list" aria-labelledby={`${id}-l`}>
        {value.length === 0 && <span className="hint">None linked</span>}
        {value.map((r) => (
          <span className="chip" role="listitem" key={`${r.type}:${r.id}`}>
            <button className="ghost" onClick={() => onOpen?.(r)} title="Open" style={{ padding: 0, minHeight: 0 }}>{typeLabel(r.type)}: {labelOf(model, r)}</button>
            <button aria-label={`Remove ${labelOf(model, r)}`} onClick={() => onChange(value.filter((x) => !(x.type === r.type && x.id === r.id)))}>×</button>
          </span>
        ))}
      </div>
      <select aria-label={`Add to ${label}`} value="" onChange={(e) => { const [t, i] = e.target.value.split('|'); if (t && i) onChange([...value, { type: t as RefType, id: i }]); }} style={{ marginTop: 6 }}>
        <option value="">Add…</option>
        {(types ?? REF_TYPES.map((x) => x.type)).map((t) => {
          const group = free.filter((f) => f.type === t);
          return group.length ? <optgroup key={t} label={typeLabel(t) + 's'}>{group.map((f) => <option key={f.id} value={`${f.type}|${f.id}`}>{labelOf(model, f)}</option>)}</optgroup> : null;
        })}
      </select>
    </div>
  );
}

/* ---------------- dialogs ---------------- */
const openModals: Array<() => void> = [];
export function Modal({ title, children, onClose, wide }: { title: string; children: ReactNode; onClose: () => void; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  const prev = useRef<Element | null>(null);
  useEffect(() => {
    prev.current = document.activeElement;
    const first = ref.current?.querySelector<HTMLElement>('textarea, input, select, button.primary, button');
    first?.focus();
    // Escape must close the top-most dialog wherever focus happens to be, not only when it is inside the dialog.
    const handle = () => onClose();
    openModals.push(handle);
    const onDoc = (e: KeyboardEvent) => { if (e.key === 'Escape' && openModals[openModals.length - 1] === handle) { e.stopPropagation(); handle(); } };
    document.addEventListener('keydown', onDoc);
    return () => { document.removeEventListener('keydown', onDoc); const i = openModals.indexOf(handle); if (i >= 0) openModals.splice(i, 1); (prev.current as HTMLElement | null)?.focus?.(); };
  }, []);
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Tab') { // keep focus inside the dialog
      const f = ref.current?.querySelectorAll<HTMLElement>('a[href], button:not(:disabled), input, select, textarea, [tabindex]:not([tabindex="-1"])');
      if (!f?.length) return;
      const a = f[0]!, z = f[f.length - 1]!;
      if (e.shiftKey && document.activeElement === a) { e.preventDefault(); z.focus(); }
      else if (!e.shiftKey && document.activeElement === z) { e.preventDefault(); a.focus(); }
    }
  };
  return (
    <div className="scrim" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="dialog" role="dialog" aria-modal="true" aria-label={title} ref={ref} onKeyDown={onKey} style={wide ? { maxWidth: 860 } : undefined}>
        <h2>{title}</h2>
        {children}
      </div>
    </div>
  );
}

interface AskOptions { title: string; body?: ReactNode; label?: string; required?: boolean; confirmLabel?: string; danger?: boolean; placeholder?: string; initial?: string; noInput?: boolean }
interface DialogApi { ask: (o: AskOptions) => Promise<string | null>; toast: (msg: string) => void }
const DialogCtx = createContext<DialogApi>({ ask: async () => null, toast: () => {} });
export const useDialogs = () => useContext(DialogCtx);

export function DialogHost({ children }: { children: ReactNode }) {
  const [dlg, setDlg] = useState<(AskOptions & { resolve: (v: string | null) => void }) | null>(null);
  const [toastMsg, setToast] = useState<string | null>(null);
  const [text, setText] = useState('');
  const ask = useCallback((o: AskOptions) => new Promise<string | null>((resolve) => { setText(o.initial ?? ''); setDlg({ ...o, resolve }); }), []);
  const toast = useCallback((m: string) => { setToast(m); setTimeout(() => setToast((c) => (c === m ? null : c)), 6000); }, []);
  const close = (v: string | null) => { dlg?.resolve(v); setDlg(null); };
  const valid = !dlg?.required || text.trim().length > 0;
  return (
    <DialogCtx.Provider value={{ ask, toast }}>
      {children}
      {dlg && (
        <Modal title={dlg.title} onClose={() => close(null)}>
          <form onSubmit={(e) => { e.preventDefault(); if (valid) close(text); }}>
            {dlg.body}
            {!dlg.noInput && (
              <div className="field"><label className="lbl" htmlFor="dlg-input">{dlg.label ?? 'Reason'}{dlg.required ? ' *' : ''}</label>
                <textarea id="dlg-input" value={text} onChange={(e) => setText(e.target.value)} placeholder={dlg.placeholder} rows={3} aria-required={dlg.required} autoFocus />
              </div>
            )}
            <div className="actions">
              <button type="button" onClick={() => close(null)}>Cancel</button>
              <button type="submit" className={dlg.danger ? 'danger' : 'primary'} disabled={!valid}>{dlg.confirmLabel ?? 'Confirm'}</button>
            </div>
          </form>
        </Modal>
      )}
      {toastMsg && <div className="toast" role="status" aria-live="polite">{toastMsg}<button onClick={() => setToast(null)}>Dismiss</button></div>}
    </DialogCtx.Provider>
  );
}

export const Empty = ({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) => (
  <div className="empty"><h2>{title}</h2><p>{children}</p>{action}</div>
);

export function fmtTime(iso?: string) { if (!iso) return ''; return iso.replace('T', ' ').replace(/:\d\dZ$/, 'Z'); }
