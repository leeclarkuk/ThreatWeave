import { useEffect, useState } from 'react';
import { api, type SettingsPayload } from './api';
import { Modal, SelectField, TextField, useDialogs } from './ui';

type S = SettingsPayload['settings'];

export function SettingsDialog({ onClose, onSaved }: { onClose: () => void; onSaved: (s: S) => void }) {
  const { toast } = useDialogs();
  const [data, setData] = useState<SettingsPayload | null>(null);
  const [s, setS] = useState<S | null>(null);
  const [key, setKey] = useState('');
  const [test, setTest] = useState<string>('');
  const [theme, setTheme] = useState<string>(() => { try { return localStorage.getItem('tw.theme') ?? 'system'; } catch { return 'system'; } });
  useEffect(() => { api.settings().then((d) => { setData(d); setS(d.settings); }); }, []);
  if (!data || !s) return <Modal title="Settings" onClose={onClose}><p>Loading…</p></Modal>;
  const ai = s.ai;
  const setAi = (patch: Partial<S['ai']>) => setS({ ...s, ai: { ...ai, ...patch } });
  const which = ai.adapter === 'anthropic' ? 'anthropic' : 'openaiCompatible';
  const dirty = JSON.stringify(s) !== JSON.stringify(data.settings);
  const secret = data.secrets[which];
  const num = (v: string, d: number) => (Number.isFinite(Number(v)) && v.trim() !== '' ? Number(v) : d);
  const save = async () => { await api.putSettings(s); onSaved(s); const d = await api.settings(); setData(d); toast('Settings saved.'); };
  const applyTheme = (t: string) => { setTheme(t); try { localStorage.setItem('tw.theme', t); } catch { /* ignore */ } if (t === 'system') document.documentElement.removeAttribute('data-theme'); else document.documentElement.setAttribute('data-theme', t); };
  return (
    <Modal title="Settings" onClose={onClose} wide>
      <div className="stack">
        <section><h3>You</h3>
          <TextField label="Your name" value={s.actor} onCommit={(v) => setS({ ...s, actor: v })} hint="Recorded on every decision, status attestation and note you make. Stored locally; exported models carry it." />
          <SelectField label="Theme" value={theme} onChange={applyTheme} options={[{ value: 'system', label: 'Follow system' }, { value: 'light', label: 'Light' }, { value: 'dark', label: 'Dark' }]} />
        </section>
        <section><h3>AI assistance (optional)</h3>
          <p className="hint">Manual threat modelling needs no provider. If you add one, project text is sent only when you start an analysis and confirm what will be sent.</p>
          <SelectField label="Provider adapter" value={ai.adapter} onChange={(v) => setAi({ adapter: v })} options={[{ value: 'anthropic', label: 'Anthropic Messages API' }, { value: 'openai-compatible', label: 'OpenAI-compatible chat completions' }]} />
          {ai.adapter === 'anthropic' ? (
            <>
              <TextField label="Model identifier" required value={ai.anthropic.model} onCommit={(v) => setAi({ anthropic: { ...ai.anthropic, model: v.trim() } })} hint="Nothing is hard-coded. Enter an identifier from your provider's model list." />
              <TextField label="Base URL" value={ai.anthropic.baseUrl} onCommit={(v) => setAi({ anthropic: { ...ai.anthropic, baseUrl: v.trim() } })} />
            </>
          ) : (
            <>
              <TextField label="Base URL (including /v1)" value={ai.openaiCompatible.baseUrl} onCommit={(v) => setAi({ openaiCompatible: { ...ai.openaiCompatible, baseUrl: v.trim() } })} hint="The adapter calls POST {base}/chat/completions." />
              <TextField label="Model identifier" required value={ai.openaiCompatible.model} onCommit={(v) => setAi({ openaiCompatible: { ...ai.openaiCompatible, model: v.trim() } })} />
              <SelectField label="JSON mode" value={ai.openaiCompatible.jsonMode} onChange={(v) => setAi({ openaiCompatible: { ...ai.openaiCompatible, jsonMode: v } })} options={[{ value: 'json_object', label: 'json_object (widely supported)' }, { value: 'json_schema', label: 'json_schema (if your server supports it)' }, { value: 'none', label: 'none (prompt only)' }]} />
              <SelectField label="Output token parameter" value={ai.openaiCompatible.maxTokensParam} onChange={(v) => setAi({ openaiCompatible: { ...ai.openaiCompatible, maxTokensParam: v } })} options={[{ value: 'max_tokens', label: 'max_tokens' }, { value: 'max_completion_tokens', label: 'max_completion_tokens' }]} />
            </>
          )}
          <div className="card" style={{ background: 'var(--surface-2)' }}>
            <strong>Credential</strong>
            <p className="hint" style={{ margin: '4px 0' }}>{secret.configured ? `Configured (${secret.source === 'env' ? `from environment variable ${secret.envNames.join(' or ')}` : 'stored in the local data directory'}).` : `Not configured. Set ${secret.envNames[0]} in the environment, or save one here.`} The key is never sent to your browser after saving, never written into models, and never logged. Saved keys are kept in plaintext in <code>config.json</code> (file mode 0600) in the data directory: treat it like <code>~/.aws/credentials</code>. Prefer the environment variable on shared machines.</p>
            <div className="row"><label className="grow" style={{ margin: 0 }}><span className="sr">API key</span><input type="password" autoComplete="off" placeholder={secret.configured ? '(saved) enter a new key to replace' : 'API key (optional for local servers)'} value={key} onChange={(e) => setKey(e.target.value)} aria-label="API key" /></label>
              <button disabled={!key} onClick={async () => { await api.putSecret(which, key); setKey(''); setData(await api.settings()); toast('Key saved locally.'); }}>Save key</button>
              {secret.source === 'file' && <button className="danger" onClick={async () => { await api.putSecret(which, ''); setData(await api.settings()); }}>Remove</button>}</div>
          </div>
          <h3 style={{ marginTop: 14 }}>Budgets</h3>
          <div className="row wrap">
            {([['maxInputTokens', 'Max input tokens (estimate)'], ['maxOutputTokens', 'Max output tokens'], ['maxTotalTokens', 'Max total tokens per run'], ['maxRetries', 'Retries (max 3)'], ['timeoutSeconds', 'Timeout (seconds)']] as const).map(([k, l]) => (
              <div key={k} style={{ width: 170 }}><TextField label={l} value={String(ai.budgets[k])} onCommit={(v) => setAi({ budgets: { ...ai.budgets, [k]: num(v, ai.budgets[k]) } })} /></div>))}
          </div>
          <div className="row wrap">
            <div style={{ width: 200 }}><TextField label="USD per million input tokens" value={ai.prices ? String(ai.prices.inputPerMTok) : ''} onCommit={(v) => setAi({ prices: v.trim() ? { inputPerMTok: num(v, 0), outputPerMTok: ai.prices?.outputPerMTok ?? 0 } : null })} hint="Leave blank: cost is then reported as unavailable." /></div>
            <div style={{ width: 200 }}><TextField label="USD per million output tokens" value={ai.prices ? String(ai.prices.outputPerMTok) : ''} onCommit={(v) => setAi({ prices: { inputPerMTok: ai.prices?.inputPerMTok ?? 0, outputPerMTok: num(v, 0) } })} /></div>
            <div style={{ width: 200 }}><TextField label="Max cost per run (USD)" value={ai.budgets.maxCostUsd === null ? '' : String(ai.budgets.maxCostUsd)} onCommit={(v) => setAi({ budgets: { ...ai.budgets, maxCostUsd: v.trim() ? num(v, 0) : null } })} hint="Needs prices above." /></div>
          </div>
          <div className="callout" style={{ marginTop: 8 }}><strong>{dirty ? 'Saved adapter' : 'This adapter'}</strong> ({data.active.capabilities.displayName}) sends to <span className="mono">{data.active.host}</span>.{dirty && <> <em>You have unsaved changes. Save to see the description for the selected adapter.</em></>}
            <ul className="kvlist">{data.active.capabilities.notes.map((n, i) => <li key={i}>{n}</li>)}</ul></div>
          <div className="row" style={{ marginTop: 8 }}>
            <button onClick={async () => { setTest('Testing…'); await api.putSettings(s); const r = await api.testAi(); setTest(r.ok ? `Reachable: ${r.host}, ${r.ms} ms. Usage ${r.usage?.inputTokens ?? 'n/a'} in / ${r.usage?.outputTokens ?? 'n/a'} out.` : `Failed: ${r.error}`); }}>Test connection</button>
            <span className="hint" role="status">{test || `Sends one tiny request ("ping") to ${data.active.host}. No project data.`}</span>
          </div>
        </section>
      </div>
      <div className="actions"><button onClick={onClose}>Close</button><button className="primary" onClick={save}>Save settings</button></div>
    </Modal>
  );
}
