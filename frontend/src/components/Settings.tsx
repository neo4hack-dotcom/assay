import { CheckCircle2, Plug, RefreshCw, Save, Server, XCircle } from 'lucide-react';
import { useEffect, useState } from 'react';
import { api } from '../api';
import type { LlmSettings, LlmTestReport, ScannerInfo, ScannerSettings, SettingsResponse } from '../types';
import { Button, Card, Field, Pill, Segmented, Spinner, Toggle, cls, inputCls, useToast } from './ui';

const PRESETS: { label: string; url: string; hint: string }[] = [
  { label: 'Ollama', url: 'http://localhost:11434/v1', hint: 'Set OLLAMA_CONTEXT_LENGTH ≥ 16384' },
  { label: 'vLLM', url: 'http://localhost:8000/v1', hint: '--max-model-len defines the context' },
  { label: 'LM Studio', url: 'http://localhost:1234/v1', hint: '' },
  { label: 'llama.cpp', url: 'http://localhost:8080/v1', hint: '-c defines the context' },
  { label: 'LiteLLM', url: 'http://localhost:4000/v1', hint: 'corporate gateway' },
];

export function Settings({ onSaved }: { onSaved: () => void }) {
  const [data, setData] = useState<SettingsResponse | null>(null);
  const [llm, setLlm] = useState<LlmSettings | null>(null);
  const [sc, setSc] = useState<ScannerSettings | null>(null);
  const [scanners, setScanners] = useState<ScannerInfo[]>([]);
  const [models, setModels] = useState<string[]>([]);
  const [report, setReport] = useState<LlmTestReport | null>(null);
  const [busy, setBusy] = useState('');
  const [headers, setHeaders] = useState('');
  const toast = useToast();

  useEffect(() => {
    api.settings().then((d) => { setData(d); setLlm(d.llm); setSc(d.scanners); setHeaders(Object.entries(d.llm.extra_headers).map(([k, v]) => `${k}: ${v}`).join('\n')); })
      .catch((e) => toast(e.message, 'error'));
    api.scanners().then(setScanners).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  if (!llm || !sc || !data) return <Spinner label="Loading settings…" />;

  const body = (): LlmSettings => ({
    ...llm,
    extra_headers: Object.fromEntries(headers.split('\n').map((l) => l.split(':')).filter((p) => p.length >= 2 && p[0].trim())
      .map(([k, ...rest]) => [k.trim(), rest.join(':').trim()])),
  });
  const set = <K extends keyof LlmSettings>(k: K, v: LlmSettings[K]) => setLlm({ ...llm, [k]: v });

  const fetchModels = async () => {
    setBusy('models');
    try { const r = await api.listModels(body()); setModels(r.models); toast(`${r.models.length} model(s) found`); } catch (e) { toast((e as Error).message, 'error'); } finally { setBusy(''); }
  };
  const test = async () => {
    setBusy('test'); setReport(null);
    try { const r = await api.testLlm(body()); setReport(r); if (r.models?.length) setModels(r.models); } catch (e) { toast((e as Error).message, 'error'); } finally { setBusy(''); }
  };
  const save = async () => {
    setBusy('save');
    try { const r = await api.saveLlm(body()); setLlm(r); toast('LLM settings saved'); onSaved(); } catch (e) { toast((e as Error).message, 'error'); } finally { setBusy(''); }
  };
  const saveScanners = async () => {
    try { await api.saveScanners(sc); toast('Scanner settings saved'); } catch (e) { toast((e as Error).message, 'error'); }
  };

  return (
    <div className="mx-auto max-w-4xl space-y-5">
      <div><h1 className="text-2xl font-bold">Settings</h1><p className="text-sm text-zinc-500">Connect your internal LLM through any OpenAI-compatible endpoint.</p></div>

      <Card title={<span className="inline-flex items-center gap-2"><Plug size={15} />LLM endpoint (OpenAI-compatible)</span>}>
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2">
            {PRESETS.map((p) => (
              <button key={p.label} type="button" title={p.hint} onClick={() => set('base_url', p.url)}
                className={cls('rounded-md border px-2.5 py-1 text-xs', llm.base_url === p.url ? 'border-brand-500 bg-brand-50 text-brand-700 dark:bg-brand-950 dark:text-brand-300' : 'border-zinc-300 dark:border-zinc-700')}>{p.label}</button>
            ))}
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Base URL" hint="Must include the API prefix, usually /v1. Azure: https://<res>.openai.azure.com/openai/deployments/<deployment>">
              <input className={inputCls} value={llm.base_url} onChange={(e) => set('base_url', e.target.value)} placeholder="http://llm.corp.local:8000/v1" />
            </Field>
            <Field label="API key" hint={llm.api_key_set ? 'A key is stored. Type a new one to replace it.' : 'Leave empty if the endpoint needs none.'}>
              <input className={inputCls} type="password" value={llm.api_key} onChange={(e) => set('api_key', e.target.value)} placeholder="sk-…" autoComplete="off" />
            </Field>
            <Field label="Model">
              <div className="flex gap-2">
                <input className={inputCls} list="assay-models" value={llm.model} onChange={(e) => set('model', e.target.value)} placeholder="qwen2.5-coder:32b" />
                <datalist id="assay-models">{models.map((m) => <option key={m} value={m} />)}</datalist>
                <Button variant="outline" icon={RefreshCw} busy={busy === 'models'} onClick={fetchModels} title="List models from the endpoint">List</Button>
              </div>
            </Field>
            <Field label="Authentication header">
              <Segmented value={llm.auth_header} onChange={(v) => set('auth_header', v)} options={[{ value: 'bearer', label: 'Bearer' }, { value: 'api-key', label: 'api-key (Azure)' }, { value: 'none', label: 'None' }]} />
            </Field>
            <Field label="Context window (tokens)" hint="Must match what the server really allows; larger = more code reviewed per call.">
              <input type="number" className={inputCls} value={llm.context_window} onChange={(e) => set('context_window', Number(e.target.value))} />
            </Field>
            <Field label="Max output tokens"><input type="number" className={inputCls} value={llm.max_output_tokens} onChange={(e) => set('max_output_tokens', Number(e.target.value))} /></Field>
            <Field label="Temperature"><input type="number" step="0.05" className={inputCls} value={llm.temperature} onChange={(e) => set('temperature', Number(e.target.value))} /></Field>
            <Field label="Parallel requests"><input type="number" min={1} max={32} className={inputCls} value={llm.max_concurrency} onChange={(e) => set('max_concurrency', Number(e.target.value))} /></Field>
            <Field label="Request timeout (s)"><input type="number" className={inputCls} value={llm.timeout_s} onChange={(e) => set('timeout_s', Number(e.target.value))} /></Field>
            <Field label="API version (Azure only)"><input className={inputCls} value={llm.api_version} onChange={(e) => set('api_version', e.target.value)} placeholder="2024-10-21" /></Field>
            <Field label="Corporate CA bundle (path on the Assay host)" hint="For endpoints signed by an internal PKI."><input className={inputCls} value={llm.ca_bundle} onChange={(e) => set('ca_bundle', e.target.value)} placeholder="C:\\certs\\corp-ca.pem" /></Field>
            <Field label="Extra headers (one per line, Name: value)"><textarea className={cls(inputCls, 'h-[42px] font-mono text-xs')} value={headers} onChange={(e) => setHeaders(e.target.value)} placeholder="X-Tenant: audit" /></Field>
          </div>
          <div className="flex flex-wrap gap-5">
            <Toggle checked={llm.json_mode} onChange={(v) => set('json_mode', v)} label="Request JSON mode (auto-disabled if unsupported)" />
            <Toggle checked={llm.verify_tls} onChange={(v) => set('verify_tls', v)} label="Verify TLS certificates" />
          </div>
          <div className="flex flex-wrap justify-end gap-2">
            <Button variant="outline" icon={Plug} busy={busy === 'test'} onClick={test}>Test connection</Button>
            <Button icon={Save} busy={busy === 'save'} onClick={save}>Save</Button>
          </div>
          {report && (
            <div className={cls('rounded-lg border p-3', report.ok ? 'border-green-200 bg-green-50 dark:border-green-900 dark:bg-green-950/40' : 'border-red-200 bg-red-50 dark:border-red-900 dark:bg-red-950/40')}>
              <div className="mb-2 flex flex-wrap items-center gap-2 text-sm font-semibold">
                {report.ok ? <CheckCircle2 size={16} className="text-green-600" /> : <XCircle size={16} className="text-red-600" />}
                {report.ok ? 'Connection OK' : 'Connection failed'}
                {report.latency_ms != null && <Pill>{report.latency_ms} ms warm latency</Pill>}
                {report.tokens_per_s != null && <Pill>{report.tokens_per_s} tok/s</Pill>}
                {report.json_mode_supported != null && <Pill tone={report.json_mode_supported ? 'green' : 'amber'}>JSON mode {report.json_mode_supported ? 'supported' : 'not supported'}</Pill>}
              </div>
              <ul className="space-y-1 text-sm">
                {report.steps.map((s, i) => (
                  <li key={i} className="flex gap-2">{s.ok ? <CheckCircle2 size={14} className="mt-0.5 shrink-0 text-green-600" /> : <XCircle size={14} className="mt-0.5 shrink-0 text-red-600" />}
                    <span><b>{s.name}</b> — {s.detail}{s.ms != null && <span className="text-zinc-500"> ({s.ms} ms)</span>}</span></li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </Card>

      <Card title="External scanners">
        <p className="mb-3 text-sm text-zinc-500">Assay's own rules always run. These tools are used when installed on the Assay host and corroborate or extend the results.</p>
        <div className="mb-4 grid gap-2 sm:grid-cols-2">
          {scanners.map((s) => (
            <div key={s.name} className="flex items-center gap-2 text-sm">
              {s.available ? <CheckCircle2 size={15} className="text-green-600" /> : <XCircle size={15} className="text-zinc-400" />}
              <b>{s.name}</b><span className="truncate text-xs text-zinc-500">{s.available ? s.path : 'not installed'}</span>
            </div>
          ))}
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Scanner timeout (s)"><input type="number" className={inputCls} value={sc.timeout_s} onChange={(e) => setSc({ ...sc, timeout_s: Number(e.target.value) })} /></Field>
          <Field label="Semgrep config" hint="'auto' needs internet; air-gapped: a local rules folder path."><input className={inputCls} value={sc.semgrep_config} onChange={(e) => setSc({ ...sc, semgrep_config: e.target.value })} /></Field>
        </div>
        <div className="mt-3 flex justify-end"><Button variant="outline" icon={Save} onClick={saveScanners}>Save</Button></div>
      </Card>

      <Card title={<span className="inline-flex items-center gap-2"><Server size={15} />Server</span>}>
        <dl className="grid gap-2 text-sm sm:grid-cols-2">
          <div><dt className="text-xs text-zinc-500">Version</dt><dd>{data.server.version}</dd></div>
          <div><dt className="text-xs text-zinc-500">Listening on</dt><dd>{data.server.host}:{data.server.port}</dd></div>
          <div><dt className="text-xs text-zinc-500">Data folder</dt><dd className="break-all font-mono text-xs">{data.server.data_dir}</dd></div>
          <div><dt className="text-xs text-zinc-500">Access token</dt><dd>{data.server.auth_required ? <Pill tone="green">required</Pill> : <Pill tone="amber">not set (ASSAY_AUTH_TOKEN)</Pill>}</dd></div>
          <div><dt className="text-xs text-zinc-500">Allowed folders</dt><dd className="font-mono text-xs">{data.server.allowed_roots.join(', ') || 'any (ASSAY_ALLOWED_ROOTS not set)'}</dd></div>
          <div><dt className="text-xs text-zinc-500">Custom rules folder</dt><dd className="break-all font-mono text-xs">{data.server.custom_rules_dir}</dd></div>
        </dl>
      </Card>
    </div>
  );
}
