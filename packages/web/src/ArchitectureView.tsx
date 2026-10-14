import { useCallback, useEffect, useMemo, useState } from 'react';
import { Background, Controls, Handle, MarkerType, MiniMap, Position, ReactFlow, ReactFlowProvider, useReactFlow, type Edge, type Node, type NodeProps, type Connection } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { addEntity, removeEntity, setLayout, type ElementKind, type Model } from '@threatweave/core';
import { useWs, highlightFor } from './ctx';
import { Empty, Mark, ReviewMark, SelectField, TextField, useDialogs } from './ui';

const NODE_W = 190, NODE_H = 72, PAD = 36;
export const KIND_LABEL: Record<ElementKind, string> = { process: 'Process', datastore: 'Data store', 'external-system': 'External system', actor: 'Actor' };
const KIND_GLYPH: Record<ElementKind, string> = { process: '▢', datastore: '≡', 'external-system': '⬚', actor: '◯' };

function autoLayout(model: Model): Record<string, { x: number; y: number }> {
  if (model.flows.length === 0) {
    // No relationships to layer by: a tidy grid that fits a normal window.
    return Object.fromEntries([...model.elements].sort((a, b) => a.name.localeCompare(b.name)).map((e, i) => [e.id, { x: 60 + (i % 3) * 270, y: 60 + Math.floor(i / 3) * 130 }]));
  }
  const layer = new Map<string, number>();
  const incoming = new Map<string, string[]>();
  model.elements.forEach((e) => incoming.set(e.id, []));
  model.flows.forEach((f) => incoming.get(f.to)?.push(f.from));
  const visit = (id: string, stack: Set<string>): number => {
    if (layer.has(id)) return layer.get(id)!;
    if (stack.has(id)) return 0;
    stack.add(id);
    const ins = incoming.get(id) ?? [];
    const l = ins.length ? 1 + Math.max(...ins.map((i) => visit(i, stack))) : 0;
    stack.delete(id);
    layer.set(id, l);
    return l;
  };
  model.elements.forEach((e) => visit(e.id, new Set()));
  const rows = new Map<number, number>();
  const out: Record<string, { x: number; y: number }> = {};
  for (const e of [...model.elements].sort((a, b) => (layer.get(a.id)! - layer.get(b.id)!) || a.name.localeCompare(b.name))) {
    const l = layer.get(e.id)!;
    const r = rows.get(l) ?? 0;
    rows.set(l, r + 1);
    out[e.id] = { x: 60 + l * 300, y: 60 + r * 130 };
  }
  return out;
}

type ElData = { name: string; kind: ElementKind; exposure: string; tech: string; review: number; selected: boolean; related: boolean; dim: boolean; threats: number };
function ElementNode({ data }: NodeProps<Node<ElData>>) {
  return (
    <div className={`tw-node ${data.kind}${data.selected ? ' selected' : ''}${data.related ? ' related' : ''}${data.dim ? ' dim' : ''}`}>
      <Handle type="target" position={Position.Top} />
      {data.review > 0 && <span className="badge-review"><ReviewMark n={data.review} /></span>}
      <div className="nm">{KIND_GLYPH[data.kind]} {data.name}</div>
      <div className="meta">
        <span>{KIND_LABEL[data.kind]}</span>
        {data.exposure !== 'unknown' && <Mark kind={data.exposure === 'external' ? 'review' : 'plain'}>{data.exposure === 'external' ? '⇄ External' : 'Internal'}</Mark>}
        {data.threats > 0 && <span>{data.threats} threat{data.threats > 1 ? 's' : ''}</span>}
      </div>
      {data.tech && <div className="meta">{data.tech}</div>}
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}
type BData = { name: string; trust: string; selected: boolean; related: boolean; flip: boolean; onPick: () => void };
function BoundaryNode({ data }: NodeProps<Node<BData>>) {
  return (
    <div className={`tw-boundary ${data.trust}${data.selected ? ' selected' : ''}${data.related ? ' related' : ''}`} style={{ width: '100%', height: '100%' }}>
      <button className="tag" style={{ minHeight: 0, padding: '0 8px', ...(data.flip ? { top: 'auto', bottom: -12 } : {}) }} onClick={data.onPick}>▭ {data.name} · {data.trust === 'unknown' ? 'trust not set' : data.trust}</button>
    </div>
  );
}
const nodeTypes = { el: ElementNode, boundary: BoundaryNode };

function CanvasInner() {
  const { session, model, selection, select, actor } = useWs();
  const { toast } = useDialogs();
  const hl = useMemo(() => highlightFor(model, selection), [model, selection]);
  const hasSel = !!selection && (hl.elements.size > 0 || hl.flows.size > 0 || hl.boundaries.size > 0);
  const auto = useMemo(() => autoLayout(model), [model.elements.length, model.flows.length]);
  const pos = (id: string) => model.view.layout[id] ?? auto[id] ?? { x: 0, y: 0 };
  const reviewCount = useMemo(() => {
    const m = new Map<string, number>();
    for (const r of model.reviewItems) if (r.status === 'open') m.set(r.target.id, (m.get(r.target.id) ?? 0) + 1);
    return m;
  }, [model.reviewItems]);

  const nodes: Node[] = useMemo(() => {
    const out: Node[] = [];
    let bi = 0;
    for (const b of model.boundaries) {
      const ms = b.memberIds.filter((id) => model.elements.some((e) => e.id === id)).map(pos);
      if (!ms.length) continue;
      const minX = Math.min(...ms.map((p) => p.x)) - PAD, minY = Math.min(...ms.map((p) => p.y)) - PAD - 8;
      const maxX = Math.max(...ms.map((p) => p.x)) + NODE_W + PAD, maxY = Math.max(...ms.map((p) => p.y)) + NODE_H + PAD;
      out.push({ id: `b:${b.id}`, type: 'boundary', position: { x: minX, y: minY }, style: { width: maxX - minX, height: maxY - minY, pointerEvents: 'none' }, selectable: false, draggable: false, focusable: false, zIndex: -1,
        data: { name: b.name, trust: b.trust, selected: selection?.type === 'boundary' && selection.id === b.id, related: hl.boundaries.has(b.id), flip: bi++ % 2 === 1, onPick: () => select({ type: 'boundary', id: b.id }) } satisfies BData });
    }
    for (const e of model.elements) {
      const threats = model.threats.filter((t) => t.targets.some((r) => r.type === 'element' && r.id === e.id)).length;
      out.push({ id: e.id, type: 'el', position: pos(e.id), selected: selection?.type === 'element' && selection.id === e.id, ariaLabel: `${KIND_LABEL[e.kind]} ${e.name}, ${e.exposure}`,
        data: { name: e.name, kind: e.kind, exposure: e.exposure, tech: e.technology, review: reviewCount.get(e.id) ?? 0, threats, selected: selection?.type === 'element' && selection.id === e.id, related: hl.elements.has(e.id) && !(selection?.type === 'element' && selection.id === e.id), dim: hasSel && !hl.elements.has(e.id) } satisfies ElData });
    }
    return out;
  }, [model, selection, hl, hasSel, auto, reviewCount]);

  const edges: Edge[] = useMemo(() => model.flows.map((f) => {
    const on = hl.flows.has(f.id), sel = selection?.type === 'flow' && selection.id === f.id;
    const bits = [f.label || f.protocol, f.encrypted === 'no' ? 'cleartext' : '', f.authenticated === 'no' ? 'no auth' : ''].filter(Boolean).join(' · ');
    const rv = reviewCount.get(f.id);
    return {
      id: f.id, source: f.from, target: f.to, label: `${rv ? '◆ ' : ''}${bits}`, selected: sel, ariaLabel: `Data flow ${bits || 'unlabelled'}`,
      markerEnd: { type: MarkerType.ArrowClosed, width: 18, height: 18 },
      style: { strokeWidth: sel || on ? 3.2 : 1.8, strokeDasharray: f.basis === 'observed' ? undefined : '7 4', opacity: hasSel && !on ? 0.35 : 1 },
    } satisfies Edge;
  }), [model.flows, hl, hasSel, selection, reviewCount]);

  const { fitView } = useReactFlow();
  useEffect(() => {
    const fit = () => setTimeout(() => void fitView({ padding: 0.1, maxZoom: 1.15, duration: 150 }), 60);
    const t = fit();
    window.addEventListener('tw-fit', fit);
    return () => { clearTimeout(t); window.removeEventListener('tw-fit', fit); };
  }, [model.elements.length, fitView]);

  const onConnect = useCallback((c: Connection) => {
    if (!c.source || !c.target) return;
    const dup = model.flows.some((f) => f.from === c.source && f.to === c.target);
    if (dup && !confirm('A flow between these components already exists. Add another?')) return;
    let newId = '';
    session.mutate('Add data flow', (m) => { const r = addEntity(m, 'flow', { from: c.source, to: c.target, label: '' }, actor); newId = r.id; return r.model; }, { immediate: true });
    if (newId) select({ type: 'flow', id: newId });
  }, [model.flows, session, select, actor]);

  return (
    <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.08, maxZoom: 1.15 }} minZoom={0.2} maxZoom={1.8}
      nodesConnectable edgesFocusable deleteKeyCode={['Backspace', 'Delete']} proOptions={{ hideAttribution: false }}
      onNodeClick={(_, n) => { if (n.type === 'el') select({ type: 'element', id: n.id }); }}
      onEdgeClick={(_, e) => select({ type: 'flow', id: e.id })}
      onPaneClick={() => select(null)}
      onNodeDragStop={(_, n) => { if (n.type === 'el') session.mutate('Move component', (m) => setLayout(m, { [n.id]: { x: Math.round(n.position.x), y: Math.round(n.position.y) } })); }}
      onConnect={onConnect}
      onNodesDelete={(ns) => { const els = ns.filter((n) => n.type === 'el'); if (els.length) { session.mutate(`Delete ${els.length} component(s)`, (m) => els.reduce((acc, n) => removeEntity(acc, 'element', n.id), m), { immediate: true }); select(null); toast(`Deleted ${els.length} component(s) and their flows. Undo with Ctrl+Z.`); } }}
      onEdgesDelete={(es) => { const ids = es.map((e) => e.id).filter((id) => session.model.flows.some((f) => f.id === id)); if (ids.length) session.mutate('Delete flow', (m) => ids.reduce((acc, id) => removeEntity(acc, 'flow', id), m), { immediate: true }); }}
    >
      <Background gap={20} />
      <Controls showInteractive={false} />
      {model.elements.length > 12 && <MiniMap pannable zoomable nodeColor="#8f8873" nodeStrokeColor="#444e63" nodeStrokeWidth={2} ariaLabel="Diagram overview" />}
    </ReactFlow>
  );
}

/** Table alternative: every essential canvas operation, with no pointer required. */
function TableView() {
  const { session, model, selection, select, actor } = useWs();
  const { toast, ask } = useDialogs();
  const [name, setName] = useState('');
  const [kind, setKind] = useState<ElementKind>('process');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [bname, setBname] = useState('');
  const sel = (t: string, id: string) => selection?.type === t && selection.id === id;
  const reviewCount = (id: string) => model.reviewItems.filter((r) => r.status === 'open' && r.target.id === id).length;
  const nm = (id: string) => model.elements.find((e) => e.id === id)?.name ?? id;
  const addEl = () => { if (!name.trim()) return; let id = ''; session.mutate('Add component', (m) => { const r = addEntity(m, 'element', { name: name.trim(), kind }, actor); id = r.id; return r.model; }, { immediate: true }); setName(''); if (id) select({ type: 'element', id }); };
  const addFlow = () => { if (!from || !to) return; let id = ''; session.mutate('Add flow', (m) => { const r = addEntity(m, 'flow', { from, to }, actor); id = r.id; return r.model; }, { immediate: true }); if (id) select({ type: 'flow', id }); };
  const addB = () => { if (!bname.trim()) return; let id = ''; session.mutate('Add boundary', (m) => { const r = addEntity(m, 'boundary', { name: bname.trim() }, actor); id = r.id; return r.model; }, { immediate: true }); setBname(''); if (id) select({ type: 'boundary', id }); };
  const del = async (type: 'element' | 'flow' | 'boundary', id: string, label: string) => {
    if ((await ask({ title: `Delete ${label}?`, noInput: true, confirmLabel: 'Delete', danger: true, body: <p>{type === 'element' ? 'Its data flows and boundary memberships are removed too. ' : ''}You can undo this.</p> })) === null) return;
    session.mutate('Delete', (m) => removeEntity(m, type, id), { immediate: true }); select(null); toast(`Deleted ${label}.`);
  };
  return (
    <div className="main stack" style={{ overflow: 'auto', flex: 1 }}>
      <section aria-labelledby="t-comp">
        <h2 id="t-comp" style={{ marginBottom: 8 }}>Components</h2>
        {model.elements.length === 0 ? <p className="hint">No components yet. Add one below.</p> : (
          <table className="grid"><thead><tr><th scope="col">Name</th><th scope="col">Kind</th><th scope="col">Exposure</th><th scope="col">Technology</th><th scope="col">Related</th><th scope="col"><span className="sr">Actions</span></th></tr></thead>
            <tbody>{model.elements.map((e) => (
              <tr key={e.id} aria-selected={sel('element', e.id)}>
                <td><button className="rowbtn" onClick={() => select({ type: 'element', id: e.id })}>{e.name}</button></td>
                <td>{KIND_LABEL[e.kind]}</td>
                <td>{e.exposure === 'external' ? <Mark kind="review">⇄ External</Mark> : e.exposure}</td>
                <td>{e.technology}</td>
                <td>{model.threats.filter((t) => t.targets.some((r) => r.id === e.id)).length} threats {reviewCount(e.id) > 0 && <Mark kind="review">◆ Needs review</Mark>}</td>
                <td><button className="small danger" aria-label={`Delete ${e.name}`} onClick={() => del('element', e.id, e.name)}>Delete</button></td>
              </tr>))}</tbody></table>)}
        <form className="row wrap" style={{ marginTop: 8 }} onSubmit={(ev) => { ev.preventDefault(); addEl(); }}>
          <div className="grow"><TextField live label="New component name" value={name} onCommit={setName} /></div>
          <div style={{ width: 180 }}><SelectField label="Kind" value={kind} onChange={setKind} options={(Object.keys(KIND_LABEL) as ElementKind[]).map((k) => ({ value: k, label: KIND_LABEL[k] }))} /></div>
          <button type="submit" className="primary" style={{ marginTop: 6 }} disabled={!name.trim()}>Add component</button>
        </form>
      </section>
      <section aria-labelledby="t-flow">
        <h2 id="t-flow" style={{ marginBottom: 8 }}>Data flows</h2>
        {model.flows.length === 0 ? <p className="hint">No data flows yet.</p> : (
          <table className="grid"><thead><tr><th scope="col">From</th><th scope="col">To</th><th scope="col">Label</th><th scope="col">Authenticated</th><th scope="col">Encrypted</th><th scope="col"><span className="sr">Actions</span></th></tr></thead>
            <tbody>{model.flows.map((f) => (
              <tr key={f.id} aria-selected={sel('flow', f.id)}>
                <td><button className="rowbtn" onClick={() => select({ type: 'flow', id: f.id })}>{nm(f.from)}</button></td><td>{nm(f.to)}</td><td>{f.label || f.protocol}</td><td>{f.authenticated}</td><td>{f.encrypted}</td>
                <td><button className="small danger" aria-label={`Delete flow ${nm(f.from)} to ${nm(f.to)}`} onClick={() => del('flow', f.id, `flow ${nm(f.from)} → ${nm(f.to)}`)}>Delete</button></td>
              </tr>))}</tbody></table>)}
        <form className="row wrap" style={{ marginTop: 8 }} onSubmit={(ev) => { ev.preventDefault(); addFlow(); }}>
          <div style={{ width: 200 }}><SelectField label="From" value={from} onChange={setFrom} options={[{ value: '', label: 'Choose…' }, ...model.elements.map((e) => ({ value: e.id, label: e.name }))]} /></div>
          <div style={{ width: 200 }}><SelectField label="To" value={to} onChange={setTo} options={[{ value: '', label: 'Choose…' }, ...model.elements.map((e) => ({ value: e.id, label: e.name }))]} /></div>
          <button type="submit" className="primary" style={{ marginTop: 6 }} disabled={!from || !to}>Add flow</button>
        </form>
      </section>
      <section aria-labelledby="t-tb">
        <h2 id="t-tb" style={{ marginBottom: 8 }}>Trust boundaries</h2>
        {model.boundaries.length === 0 ? <p className="hint">No trust boundaries yet.</p> : (
          <table className="grid"><thead><tr><th scope="col">Name</th><th scope="col">Trust</th><th scope="col">Members</th><th scope="col"><span className="sr">Actions</span></th></tr></thead>
            <tbody>{model.boundaries.map((b) => (
              <tr key={b.id} aria-selected={sel('boundary', b.id)}>
                <td><button className="rowbtn" onClick={() => select({ type: 'boundary', id: b.id })}>{b.name}</button></td><td>{b.trust}</td><td>{b.memberIds.map(nm).join(', ') || 'none'}</td>
                <td><button className="small danger" aria-label={`Delete ${b.name}`} onClick={() => del('boundary', b.id, b.name)}>Delete</button></td>
              </tr>))}</tbody></table>)}
        <form className="row wrap" style={{ marginTop: 8 }} onSubmit={(ev) => { ev.preventDefault(); addB(); }}>
          <div className="grow"><TextField live label="New boundary name" value={bname} onCommit={setBname} hint="Choose members in the inspector after adding." /></div>
          <button type="submit" className="primary" style={{ marginTop: 6 }} disabled={!bname.trim()}>Add boundary</button>
        </form>
      </section>
    </div>
  );
}

export function ArchitectureView() {
  const { session, model, actor, select } = useWs();
  const { ask } = useDialogs();
  const [mode, setMode] = useState<'canvas' | 'table'>(() => { try { return (localStorage.getItem('tw.archmode') as 'canvas' | 'table') || 'canvas'; } catch { return 'canvas'; } });
  const setM = (m: 'canvas' | 'table') => { setMode(m); try { localStorage.setItem('tw.archmode', m); } catch { /* ignore */ } };
  const add = (kind: ElementKind) => {
    const n = model.elements.length;
    const names: Record<ElementKind, string> = { process: 'New service', datastore: 'New data store', 'external-system': 'New external system', actor: 'New actor' };
    let id = '';
    session.mutate(`Add ${KIND_LABEL[kind]}`, (m) => {
      const r = addEntity(m, 'element', { name: names[kind], kind }, actor);
      id = r.id;
      return setLayout(r.model, { [r.id]: { x: 80 + (n % 4) * 250, y: 80 + Math.floor(n / 4) * 140 } });
    }, { immediate: true });
    if (id) select({ type: 'element', id });
  };
  const addBoundary = async () => {
    const name = await ask({ title: 'New trust boundary', label: 'Name', required: true, placeholder: 'e.g. Internal network', confirmLabel: 'Add boundary', body: <p className="hint">Choose which components it contains in the inspector afterwards.</p> });
    if (!name) return;
    let id = '';
    session.mutate('Add boundary', (m) => { const r = addEntity(m, 'boundary', { name: name.trim() }, actor); id = r.id; return r.model; }, { immediate: true });
    if (id) select({ type: 'boundary', id });
  };
  const arrange = () => { session.mutate('Auto-arrange', (m) => { const next = structuredClone(m); next.view.layout = autoLayoutExport(m); return next; }); setTimeout(() => window.dispatchEvent(new Event('tw-fit')), 80); };
  return (
    <>
      <div className="toolbar" role="toolbar" aria-label="Architecture tools">
        <div className="group" role="group" aria-label="View">
          <button aria-pressed={mode === 'canvas'} className={mode === 'canvas' ? 'primary' : ''} onClick={() => setM('canvas')}>Canvas</button>
          <button aria-pressed={mode === 'table'} className={mode === 'table' ? 'primary' : ''} onClick={() => setM('table')}>Table</button>
        </div>
        <div className="group" role="group" aria-label="Add to diagram">
          <button onClick={() => add('process')}>＋ Service</button>
          <button onClick={() => add('datastore')}>＋ Data store</button>
          <button onClick={() => add('external-system')}>＋ External system</button>
          <button onClick={() => add('actor')}>＋ Actor</button>
          <button onClick={addBoundary}>＋ Boundary</button>
        </div>
        <button onClick={arrange} disabled={mode !== 'canvas' || model.elements.length === 0}>Auto-arrange</button>
        <span className="spacer" />
        <span className="hint">{model.elements.length} components · {model.flows.length} flows · {model.boundaries.length} boundaries</span>
      </div>
      {model.elements.length === 0 && mode === 'canvas' ? (
        <div className="main"><Empty title="Draw the system first" action={<div className="row" style={{ justifyContent: 'center' }}><button className="primary" onClick={() => add('process')}>Add a service</button><button onClick={() => setM('table')}>Use the table instead</button></div>}>
          Add components, then drag from a component's right handle to another to create a data flow. Or point the Source tab at a Docker Compose or Kubernetes folder to derive them.
        </Empty></div>
      ) : mode === 'canvas' ? (
        <div className="canvas-wrap" aria-label="Architecture diagram. A table view with the same operations is available.">
          <ReactFlowProvider><CanvasInner /></ReactFlowProvider>
          <div className="legend" aria-label="Legend">
            <span>▢ process</span><span>≡ data store</span><span>⬚ external system</span><span>◯ actor</span><span>━ observed flow</span><span>╌ inferred or assumed flow</span><span>▭ dashed box: trust boundary</span><span>◆ needs review</span>
          </div>
        </div>
      ) : <TableView />}
    </>
  );
}

function autoLayoutExport(m: Model) { return autoLayout(m); }
