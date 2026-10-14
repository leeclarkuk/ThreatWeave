/**
 * Deterministic topology extraction from a bounded set of artefacts:
 *   - Docker Compose files (services, ports, networks, depends_on, env URLs)
 *   - Kubernetes manifests (workloads, Services, Ingress)
 * Nothing here executes content; YAML is parsed as data only.
 */
import { LineCounter, parseAllDocuments, isMap, isSeq, isScalar, type Node, type Document } from 'yaml';
import type { ElementKind, Exposure, Tri } from './model.js';

export interface SourceFileInput {
  path: string;
  content: string;
  hash: string;
}
export interface DerivedEvidence {
  path: string;
  lineStart: number;
  lineEnd: number;
  quote: string;
  fileHash: string;
}
export interface DerivedElement {
  sourceKey: string;
  name: string;
  kind: ElementKind;
  technology: string;
  exposure: Exposure;
  tags: string[];
  properties: Record<string, string>;
  description: string;
  evidence: DerivedEvidence[];
}
export interface DerivedFlow {
  sourceKey: string;
  fromKey: string;
  toKey: string;
  label: string;
  protocol: string;
  encrypted: Tri;
  authenticated: Tri;
  basis: 'observed' | 'inferred';
  evidence: DerivedEvidence[];
}
export interface DerivedBoundary {
  sourceKey: string;
  name: string;
  trust: 'untrusted' | 'semi-trusted' | 'trusted' | 'unknown';
  memberKeys: string[];
  description: string;
  evidence: DerivedEvidence[];
}
export interface Extraction {
  elements: DerivedElement[];
  flows: DerivedFlow[];
  boundaries: DerivedBoundary[];
  notes: string[];
  files: Array<{ path: string; kind: 'compose' | 'kubernetes' | 'unrecognised' | 'unparseable' }>;
}

const SECRET_KEY = /(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|auth)/i;
const SECRET_URL = /(\w+:\/\/[^:/\s@]+:)([^@\s]+)(@)/g;

/** Redact secret-looking values before text is stored as evidence or sent to a provider. */
export function redactSecrets(text: string): { text: string; count: number } {
  let count = 0;
  const lines = text.split('\n').map((line) => {
    let out = line.replace(SECRET_URL, (_m, a, _b, c) => { count++; return `${a}[REDACTED]${c}`; });
    const m = /^(\s*(?:-\s*)?["']?)([A-Za-z0-9_.-]+)(["']?\s*[:=]\s*)(.+)$/.exec(out);
    if (m && SECRET_KEY.test(m[2]!) && m[4]!.trim() !== '' && !/\[REDACTED\]/.test(m[4]!) && !/^\$\{?[A-Z_]+\}?$/.test(m[4]!.trim())) {
      count++;
      out = `${m[1]}${m[2]}${m[3]}[REDACTED]`;
    }
    return out;
  });
  return { text: lines.join('\n'), count };
}

const DATASTORE = /(postgres|mysql|mariadb|mongo|redis|memcache|elasticsearch|opensearch|cassandra|couchdb|influx|minio|clickhouse|sqlite|dynamodb)/i;
const BROKER = /(kafka|rabbitmq|nats|activemq|pulsar|mosquitto)/i;

class Ctx {
  constructor(public file: SourceFileInput, public lc: LineCounter, public lines: string[]) {}
  range(node: Node | null | undefined, fallback?: Node | null): [number, number] {
    const n = node ?? fallback;
    if (!n || !n.range) return [1, 1];
    const s = this.lc.linePos(n.range[0]).line;
    const e = this.lc.linePos(Math.max(n.range[0], n.range[1] - 1)).line;
    return [s, e];
  }
  ev(start: number, end: number, maxLines = 6): DerivedEvidence {
    const e = Math.min(end, start + maxLines - 1);
    const q = redactSecrets(this.lines.slice(start - 1, e).join('\n')).text.slice(0, 580);
    return { path: this.file.path, lineStart: start, lineEnd: e, quote: q, fileHash: this.file.hash };
  }
}

const str = (n: unknown): string => (isScalar(n) ? String(n.value ?? '') : '');
function mapGet(map: Node | null | undefined, key: string): Node | null {
  if (!isMap(map)) return null;
  for (const p of map.items) if (isScalar(p.key) && String(p.key.value) === key) return (p.value as Node) ?? null;
  return null;
}
function pairOf(map: Node | null | undefined, key: string) {
  if (!isMap(map)) return undefined;
  return map.items.find((p) => isScalar(p.key) && String(p.key.value) === key);
}

function extractCompose(file: SourceFileInput, doc: Document.Parsed, lc: LineCounter, out: Extraction) {
  const ctx = new Ctx(file, lc, file.content.split('\n'));
  const services = mapGet(doc.contents as Node, 'services');
  if (!isMap(services)) return;
  const names = services.items.map((p) => str(p.key)).filter(Boolean);
  const netMembers = new Map<string, string[]>();
  const netEvidence = new Map<string, DerivedEvidence>();
  const external: string[] = [];
  const externalEvidence = new Map<string, DerivedEvidence>();
  const pre = `compose:${file.path}:`;
  const key = (n: string) => `${pre}${n}`;

  for (const p of services.items) {
    const name = str(p.key);
    if (!name) continue;
    const svc = p.value as Node;
    const [s0, e0] = ctx.range(svc, p.key as Node);
    const image = str(mapGet(svc, 'image'));
    const build = mapGet(svc, 'build');
    const technology = image || (build ? `build: ${isMap(build) ? str(mapGet(build, 'context')) : str(build)}` : '');
    const kind: ElementKind = DATASTORE.test(image) || BROKER.test(image) ? 'datastore' : 'process';
    const tags = [] as string[];
    if (BROKER.test(image)) tags.push('message-broker');
    const props: Record<string, string> = { 'source.file': file.path };
    const evidence: DerivedEvidence[] = [ctx.ev(s0, e0, 8)];

    // exposure from published ports
    let exposure: Exposure = 'internal';
    const portsNode = mapGet(svc, 'ports');
    const published: string[] = [];
    if (isSeq(portsNode)) {
      for (const it of portsNode.items) {
        if (isScalar(it)) {
          const spec = String(it.value);
          const parts = spec.replace(/\/(tcp|udp)$/i, '').split(':');
          const hostIp = parts.length === 3 ? parts[0]! : '';
          const hasHostPort = parts.length >= 2;
          if (hasHostPort) {
            if (/^(127\.0\.0\.1|localhost|::1|\[::1\])$/.test(hostIp)) props['exposure.note'] = `port ${spec} is published to loopback only`;
            else published.push(spec);
          }
        } else if (isMap(it)) {
          const pub = str(mapGet(it, 'published')), ip = str(mapGet(it, 'host_ip'));
          if (pub && !/^(127\.0\.0\.1|localhost|::1)$/.test(ip)) published.push(`${pub}:${str(mapGet(it, 'target'))}`);
        }
      }
    }
    if (str(mapGet(svc, 'network_mode')) === 'host') { published.push('network_mode: host'); }
    if (published.length) {
      exposure = 'external';
      props['exposure.reason'] = `published ports: ${published.join(', ')}`;
      const [ps, pe] = ctx.range(portsNode, pairOf(svc, 'ports')?.key as Node);
      const evp = ctx.ev(ps, pe);
      evidence.push(evp);
      external.push(name);
      externalEvidence.set(name, evp);
    }
    if (isSeq(mapGet(svc, 'expose')) || mapGet(svc, 'expose')) props['expose'] = 'declared (container-to-container only)';
    if (mapGet(svc, 'env_file')) props['env_file'] = 'referenced but not read';
    if (mapGet(svc, 'privileged') && str(mapGet(svc, 'privileged')) === 'true') {
      props['privileged'] = 'true';
      tags.push('privileged');
      evidence.push(ctx.ev(...ctx.range(pairOf(svc, 'privileged')?.key as Node, pairOf(svc, 'privileged')?.key as Node)));
    }
    if (mapGet(svc, 'volumes')) {
      const vols = mapGet(svc, 'volumes');
      if (isSeq(vols) && vols.items.some((v) => /docker\.sock/.test(str(v)))) {
        tags.push('docker-socket');
        props['mounts'] = 'docker.sock';
      }
    }
    out.elements.push({
      sourceKey: key(name), name, kind, technology, exposure, tags, properties: props,
      description: `Compose service "${name}" defined in ${file.path}.`, evidence,
    });

    // networks → boundaries
    const nets = mapGet(svc, 'networks');
    const netNames = isSeq(nets) ? nets.items.map(str) : isMap(nets) ? nets.items.map((x) => str(x.key)) : ['default'];
    for (const n of netNames.filter(Boolean)) {
      netMembers.set(n, [...(netMembers.get(n) ?? []), key(name)]);
      if (!netEvidence.has(n)) netEvidence.set(n, ctx.ev(s0, Math.min(e0, s0 + 1)));
    }
  }

  // flows from depends_on and env URLs
  const flowSeen = new Set<string>();
  const addFlow = (from: string, to: string, label: string, protocol: string, encrypted: Tri, basis: 'observed' | 'inferred', ev: DerivedEvidence) => {
    const k = `${pre}flow:${from}->${to}`;
    if (from === to) return;
    if (flowSeen.has(k)) return;
    flowSeen.add(k);
    out.flows.push({ sourceKey: k, fromKey: key(from), toKey: key(to), label, protocol, encrypted, authenticated: 'unknown', basis, evidence: [ev] });
  };
  for (const p of services.items) {
    const name = str(p.key);
    const svc = p.value as Node;
    const env = mapGet(svc, 'environment');
    const entries: Array<[string, string, Node]> = [];
    if (isMap(env)) for (const e of env.items) entries.push([str(e.key), str(e.value), e.key as Node]);
    if (isSeq(env)) for (const e of env.items) { const s = str(e); const i = s.indexOf('='); if (i > 0) entries.push([s.slice(0, i), s.slice(i + 1), e as Node]); }
    for (const [k, v, node] of entries) {
      const m = /^([a-z][a-z0-9+.-]*):\/\/(?:[^@/]*@)?([a-z0-9_.-]+)(?::\d+)?/i.exec(v.trim());
      if (m && names.includes(m[2]!)) {
        const scheme = m[1]!.toLowerCase();
        const enc: Tri = /^(https|wss|rediss|amqps|ssl|tls|mqtts)/.test(scheme) ? 'yes' : scheme === 'http' || scheme === 'ws' ? 'no' : 'unknown';
        addFlow(name, m[2]!, `${k}`, scheme, enc, 'inferred', ctx.ev(...ctx.range(node, node)));
      }
    }
    // depends_on is weaker evidence than a configured URL, so it only adds flows not already found
    const dep = mapGet(svc, 'depends_on');
    const deps = isSeq(dep) ? dep.items.map(str) : isMap(dep) ? dep.items.map((x) => str(x.key)) : [];
    for (const d of deps) if (names.includes(d)) {
      const dp = pairOf(svc, 'depends_on')!;
      addFlow(name, d, 'depends_on', '', 'unknown', 'inferred', ctx.ev(...ctx.range(dp.key as Node, dp.key as Node)));
    }
  }

  // boundaries per network
  for (const [n, members] of netMembers) {
    out.boundaries.push({
      sourceKey: `${pre}net:${n}`, name: `Compose network "${n}"`, trust: 'trusted', memberKeys: members,
      description: `Services attached to the ${n} network in ${file.path}. Network isolation is a configuration observation, not a verified control.`,
      evidence: [netEvidence.get(n)!],
    });
  }
  // external clients actor + flows
  if (external.length) {
    const ck = `${pre}@clients`;
    out.elements.push({
      sourceKey: ck, name: 'External clients', kind: 'actor', technology: '', exposure: 'external', tags: ['derived'],
      properties: { 'source.file': file.path }, description: 'Anything able to reach a published host port. Derived from port publishing, not observed traffic.',
      evidence: external.map((n) => externalEvidence.get(n)!).filter(Boolean),
    });
    out.boundaries.push({
      sourceKey: `${pre}public`, name: 'Public side of published ports', trust: 'untrusted', memberKeys: [ck],
      description: 'Where clients reaching published ports sit. Whether that is the internet or a private network depends on the host and is not known from the file.', evidence: [],
    });
    for (const n of external) addFlow('@clients', n, 'published port', '', 'unknown', 'inferred', externalEvidence.get(n)!);
    // addFlow uses key(from) so '@clients' resolves to the actor key
  }
}

const K8S_WORKLOADS = new Set(['Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'Job', 'CronJob']);

function extractK8s(file: SourceFileInput, docs: Document.Parsed[], lc: LineCounter, out: Extraction) {
  const ctx = new Ctx(file, lc, file.content.split('\n'));
  type W = { name: string; ns: string; labels: Record<string, string>; node: Node; image: string; privileged: boolean };
  const workloads: W[] = [];
  const services: Array<{ name: string; ns: string; type: string; selector: Record<string, string>; node: Node; ports: string }> = [];
  const ingresses: Array<{ name: string; host: string; backends: string[]; node: Node }> = [];
  const map2obj = (n: Node | null): Record<string, string> => {
    const o: Record<string, string> = {};
    if (isMap(n)) for (const p of n.items) o[str(p.key)] = str(p.value);
    return o;
  };
  for (const d of docs) {
    const root = d.contents as Node | null;
    if (!isMap(root)) continue;
    const kind = str(mapGet(root, 'kind'));
    const meta = mapGet(root, 'metadata');
    const name = str(mapGet(meta, 'name'));
    const ns = str(mapGet(meta, 'namespace')) || 'default';
    if (K8S_WORKLOADS.has(kind)) {
      const spec = mapGet(root, 'spec');
      const tpl = mapGet(mapGet(spec, 'template'), 'spec');
      const labels = map2obj(mapGet(mapGet(mapGet(spec, 'template'), 'metadata'), 'labels'));
      const containers = mapGet(tpl, 'containers');
      const first = isSeq(containers) ? containers.items[0] as Node : null;
      const priv = isSeq(containers) && containers.items.some((c) => str(mapGet(mapGet(c as Node, 'securityContext'), 'privileged')) === 'true');
      workloads.push({ name, ns, labels, node: root, image: str(mapGet(first, 'image')), privileged: priv });
    } else if (kind === 'Service') {
      const spec = mapGet(root, 'spec');
      const ports = mapGet(spec, 'ports');
      const pl = isSeq(ports) ? ports.items.map((x) => `${str(mapGet(x as Node, 'port'))}${mapGet(x as Node, 'nodePort') ? `/nodePort ${str(mapGet(x as Node, 'nodePort'))}` : ''}`).join(', ') : '';
      services.push({ name, ns, type: str(mapGet(spec, 'type')) || 'ClusterIP', selector: map2obj(mapGet(spec, 'selector')), node: root, ports: pl });
    } else if (kind === 'Ingress') {
      const spec = mapGet(root, 'spec');
      const rules = mapGet(spec, 'rules');
      const backends: string[] = [];
      let host = '';
      if (isSeq(rules)) for (const r of rules.items) {
        host = host || str(mapGet(r as Node, 'host'));
        const paths = mapGet(mapGet(r as Node, 'http'), 'paths');
        if (isSeq(paths)) for (const pth of paths.items) {
          const svc = mapGet(mapGet(mapGet(pth as Node, 'backend'), 'service'), 'name');
          if (svc) backends.push(str(svc));
        }
      }
      const db = mapGet(mapGet(spec, 'defaultBackend'), 'service');
      if (db) backends.push(str(mapGet(db, 'name')));
      ingresses.push({ name, host, backends, node: root });
    } else if (kind === 'NetworkPolicy') {
      out.notes.push(`${file.path}: NetworkPolicy "${name}" found but not evaluated. Exposure derived from Services and Ingress only.`);
    }
  }
  const pre = `k8s:${file.path}:`;
  const selects = (sel: Record<string, string>, labels: Record<string, string>) =>
    Object.keys(sel).length > 0 && Object.entries(sel).every(([k, v]) => labels[k] === v);
  const ext = new Map<string, DerivedEvidence>();
  const reason = new Map<string, string>();
  for (const s of services) {
    for (const w of workloads) if (w.ns === s.ns && selects(s.selector, w.labels) && (s.type === 'LoadBalancer' || s.type === 'NodePort')) {
      ext.set(w.name, ctx.ev(...ctx.range(s.node)));
      reason.set(w.name, `Service ${s.name} type ${s.type} (${s.ports})`);
    }
  }
  for (const ig of ingresses) for (const b of ig.backends) {
    const svc = services.find((s) => s.name === b);
    for (const w of workloads) if (svc && selects(svc.selector, w.labels)) {
      ext.set(w.name, ctx.ev(...ctx.range(ig.node)));
      reason.set(w.name, `Ingress ${ig.name}${ig.host ? ` host ${ig.host}` : ''} routes to Service ${b}`);
    }
  }
  for (const w of workloads) {
    const props: Record<string, string> = { 'source.file': file.path, namespace: w.ns };
    const exposed = ext.has(w.name);
    if (exposed) props['exposure.reason'] = reason.get(w.name)!;
    const tags = w.privileged ? ['privileged'] : [];
    const kind: ElementKind = DATASTORE.test(w.image) || DATASTORE.test(w.name) ? 'datastore' : 'process';
    out.elements.push({
      sourceKey: `${pre}${w.name}`, name: w.name, kind, technology: w.image, exposure: exposed ? 'external' : 'internal', tags,
      properties: props, description: `Kubernetes workload "${w.name}" in namespace ${w.ns} (${file.path}).`,
      evidence: [ctx.ev(...ctx.range(w.node), 4), ...(exposed ? [ext.get(w.name)!] : [])],
    });
  }
  // env URLs naming a Service become inferred flows to the workload that Service selects
  const flowKeys = new Set<string>();
  for (const w of workloads) {
    const spec = mapGet(mapGet(mapGet(w.node, 'spec'), 'template'), 'spec');
    const containers = mapGet(spec, 'containers');
    if (!isSeq(containers)) continue;
    for (const c of containers.items) {
      const env = mapGet(c as Node, 'env');
      if (!isSeq(env)) continue;
      for (const e of env.items) {
        const val = str(mapGet(e as Node, 'value'));
        const m = /^([a-z][a-z0-9+.-]*):\/\/([a-z0-9_.-]+)/i.exec(val);
        const svc = m && services.find((s) => s.name === m[2] && s.ns === w.ns);
        if (!m || !svc) continue;
        for (const t of workloads) if (t.ns === svc.ns && selects(svc.selector, t.labels) && t.name !== w.name) {
          const k = `${pre}flow:${w.name}->${t.name}`;
          if (flowKeys.has(k)) continue;
          flowKeys.add(k);
          const scheme = m[1]!.toLowerCase();
          out.flows.push({ sourceKey: k, fromKey: `${pre}${w.name}`, toKey: `${pre}${t.name}`, label: str(mapGet(e as Node, 'name')), protocol: scheme, encrypted: scheme === 'http' ? 'no' : /^(https|rediss|amqps)/.test(scheme) ? 'yes' : 'unknown', authenticated: 'unknown', basis: 'inferred', evidence: [ctx.ev(...ctx.range(e as Node))] });
        }
      }
    }
  }
  const nsMembers = new Map<string, string[]>();
  for (const w of workloads) nsMembers.set(w.ns, [...(nsMembers.get(w.ns) ?? []), `${pre}${w.name}`]);
  for (const [ns, members] of nsMembers)
    out.boundaries.push({
      sourceKey: `${pre}ns:${ns}`, name: `Kubernetes namespace "${ns}"`, trust: 'semi-trusted', memberKeys: members,
      description: 'Namespace membership. Not a network boundary unless NetworkPolicies enforce it, which is not evaluated.', evidence: [],
    });
  if (ext.size) {
    const ck = `${pre}@clients`;
    out.elements.push({
      sourceKey: ck, name: 'External clients', kind: 'actor', technology: '', exposure: 'external', tags: ['derived'],
      properties: { 'source.file': file.path }, description: 'Anything able to reach the Service or Ingress. Derived from manifests, not observed traffic.',
      evidence: [...ext.values()],
    });
    out.boundaries.push({ sourceKey: `${pre}public`, name: 'Outside the cluster', trust: 'untrusted', memberKeys: [ck], description: 'Callers reaching LoadBalancer, NodePort or Ingress endpoints.', evidence: [] });
    for (const [wname, ev] of ext) {
      out.flows.push({ sourceKey: `${pre}flow:@clients->${wname}`, fromKey: ck, toKey: `${pre}${wname}`, label: reason.get(wname) ?? '', protocol: '', encrypted: 'unknown', authenticated: 'unknown', basis: 'inferred', evidence: [ev] });
    }
  }
}

/** Extract topology from a bounded set of already-read files. Pure and deterministic. */
export function extractTopology(files: SourceFileInput[]): Extraction {
  const out: Extraction = { elements: [], flows: [], boundaries: [], notes: [], files: [] };
  for (const f of [...files].sort((a, b) => a.path.localeCompare(b.path))) {
    if (!/\.ya?ml$/i.test(f.path)) continue;
    const lc = new LineCounter();
    let docs: Document.Parsed[];
    try {
      docs = parseAllDocuments(f.content, { lineCounter: lc, uniqueKeys: false }) as Document.Parsed[];
    } catch (e) {
      out.files.push({ path: f.path, kind: 'unparseable' });
      out.notes.push(`${f.path}: could not be parsed as YAML (${(e as Error).message.slice(0, 120)}).`);
      continue;
    }
    if (docs.some((d) => d.errors.length)) {
      out.files.push({ path: f.path, kind: 'unparseable' });
      out.notes.push(`${f.path}: YAML errors (${docs.flatMap((d) => d.errors).map((e) => e.message).join('; ').slice(0, 160)}).`);
      continue;
    }
    const first = docs[0]?.contents as Node | null;
    if (isMap(first) && isMap(mapGet(first, 'services'))) {
      out.files.push({ path: f.path, kind: 'compose' });
      extractCompose(f, docs[0]!, lc, out);
    } else if (docs.some((d) => isMap(d.contents as Node) && mapGet(d.contents as Node, 'apiVersion') && mapGet(d.contents as Node, 'kind'))) {
      out.files.push({ path: f.path, kind: 'kubernetes' });
      extractK8s(f, docs, lc, out);
    } else out.files.push({ path: f.path, kind: 'unrecognised' });
  }
  return out;
}
