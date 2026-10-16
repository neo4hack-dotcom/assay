import { ArrowUp, FileArchive, FileText, Folder, FolderOpen, GitBranch, Play, Sparkles, Upload, X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import type { AuditContext, AuditOptions, BrowseResult, Health, ScannerInfo } from '../types';
import { Button, Card, Field, Modal, Segmented, Toggle, cls, inputCls, useToast } from './ui';

type Kind = 'path' | 'git' | 'zip';
const ALL_SCANNERS = ['bandit', 'semgrep', 'gitleaks', 'pip-audit', 'npm-audit', 'osv-scanner', 'trivy'];

export function NewAudit({ health, onCreated, onSettings }: { health: Health | null; onCreated: (id: string) => void; onSettings: () => void }) {
  const [kind, setKind] = useState<Kind>('path');
  const [location, setLocation] = useState('');
  const [ref, setRef] = useState('');
  const [subdir, setSubdir] = useState('');
  const [project, setProject] = useState('');
  const [archive, setArchive] = useState<File | null>(null);
  const [docs, setDocs] = useState<File[]>([]);
  const [ctx, setCtx] = useState<AuditContext>({ deployment: 'shared', exposure: 'internal', data_sensitivity: 'medium', expected_concurrency: 50 });
  const [useLlm, setUseLlm] = useState(true);
  const [depth, setDepth] = useState<AuditOptions['depth']>('standard');
  const [includeTests, setIncludeTests] = useState(false);
  const [scanners, setScanners] = useState<ScannerInfo[]>([]);
  const [tools, setTools] = useState<string[]>(ALL_SCANNERS);
  const [busy, setBusy] = useState(false);
  const [browsing, setBrowsing] = useState(false);
  const toast = useToast();
  const zipRef = useRef<HTMLInputElement>(null);
  const docRef = useRef<HTMLInputElement>(null);

  useEffect(() => { api.scanners().then(setScanners).catch(() => {}); }, []);
  const llmReady = !!health?.llm_configured;

  const submit = async () => {
    if (kind !== 'zip' && !location.trim()) return toast(kind === 'path' ? 'Choose a folder.' : 'Enter a git URL.', 'error');
    if (kind === 'zip' && !archive) return toast('Choose a .zip archive.', 'error');
    const payload = {
      project,
      source: { kind, location: kind === 'zip' ? archive!.name : location.trim(), ref, subdir },
      options: { use_llm: useLlm && llmReady, depth, include_tests: includeTests, external_tools: tools, context: ctx },
    };
    const form = new FormData();
    form.append('payload', JSON.stringify(payload));
    if (kind === 'zip' && archive) form.append('archive', archive);
    docs.forEach((d) => form.append('docs', d));
    setBusy(true);
    try {
      const a = await api.createAudit(form);
      toast(`Audit of ${a.project} started`);
      onCreated(a.id);
    } catch (e) {
      toast((e as Error).message, 'error');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto max-w-4xl space-y-5">
      <div>
        <h1 className="text-2xl font-bold">New audit</h1>
        <p className="text-sm text-zinc-500">Static analysis only — the audited code is never executed, installed or built.</p>
      </div>

      <Card title="1 · Source code">
        <div className="space-y-4">
          <Segmented<Kind> value={kind} onChange={setKind} options={[
            { value: 'path', label: 'Folder on the server', icon: Folder }, { value: 'git', label: 'Git repository', icon: GitBranch },
            { value: 'zip', label: 'Upload ZIP', icon: FileArchive }]} />
          {kind === 'path' && (
            <Field label="Folder path (on the machine running Assay)" hint="Windows: C:\\repos\\my-mcp · Linux: /srv/repos/my-mcp">
              <div className="flex gap-2">
                <input className={inputCls} value={location} onChange={(e) => setLocation(e.target.value)} placeholder="/path/to/mcp-server" />
                <Button variant="outline" icon={FolderOpen} onClick={() => setBrowsing(true)}>Browse</Button>
              </div>
            </Field>
          )}
          {kind === 'git' && (
            <div className="grid gap-3 sm:grid-cols-[1fr_180px]">
              <Field label="Repository URL" hint="https://, ssh:// or git@. Credentials in the URL are used once and never stored.">
                <input className={inputCls} value={location} onChange={(e) => setLocation(e.target.value)} placeholder="https://gitlab.corp/team/orders-mcp.git" />
              </Field>
              <Field label="Branch / tag (optional)"><input className={inputCls} value={ref} onChange={(e) => setRef(e.target.value)} placeholder="main" /></Field>
            </div>
          )}
          {kind === 'zip' && (
            <div>
              <input ref={zipRef} type="file" accept=".zip" className="hidden" onChange={(e) => setArchive(e.target.files?.[0] ?? null)} />
              <button type="button" onClick={() => zipRef.current?.click()}
                className="flex w-full items-center justify-center gap-2 rounded-xl border-2 border-dashed border-zinc-300 px-4 py-8 text-sm text-zinc-500 hover:border-brand-400 hover:text-brand-600 dark:border-zinc-700">
                <Upload size={18} />{archive ? `${archive.name} (${(archive.size / 1e6).toFixed(1)} MB)` : 'Choose a .zip of the MCP server source'}
              </button>
            </div>
          )}
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Project name (optional)"><input className={inputCls} value={project} onChange={(e) => setProject(e.target.value)} placeholder="derived from the source" /></Field>
            <Field label="Sub-folder to audit (optional)" hint="For monorepos, e.g. services/orders-mcp"><input className={inputCls} value={subdir} onChange={(e) => setSubdir(e.target.value)} /></Field>
          </div>
        </div>
      </Card>

      <Card title="2 · Documentation (optional)">
        <p className="mb-3 text-sm text-zinc-500">README and docs/ in the repository are used automatically. Add architecture documents, runbooks or security notes — the LLM checks the code against them.</p>
        <input ref={docRef} type="file" multiple accept=".md,.txt,.pdf,.docx,.html,.htm,.rst,.adoc" className="hidden"
          onChange={(e) => setDocs((d) => [...d, ...Array.from(e.target.files ?? [])])} />
        <div className="flex flex-wrap items-center gap-2">
          {docs.map((d, i) => (
            <span key={i} className="inline-flex items-center gap-1 rounded-md bg-zinc-100 px-2 py-1 text-xs dark:bg-zinc-800">
              <FileText size={12} />{d.name}
              <button onClick={() => setDocs(docs.filter((_, j) => j !== i))} aria-label="Remove"><X size={12} /></button>
            </span>
          ))}
          <Button variant="outline" size="sm" icon={Upload} onClick={() => docRef.current?.click()}>Add documents</Button>
        </div>
      </Card>

      <Card title="3 · Deployment context — drives severity">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Deployment" hint="A stdio-only server is fine locally, a blocker as a shared service.">
            <Segmented value={ctx.deployment} onChange={(v) => setCtx({ ...ctx, deployment: v })} options={[{ value: 'shared', label: 'Shared service' }, { value: 'local', label: 'Local / single user' }]} />
          </Field>
          <Field label="Network exposure">
            <Segmented value={ctx.exposure} onChange={(v) => setCtx({ ...ctx, exposure: v })} options={[{ value: 'internal', label: 'Internal network' }, { value: 'internet', label: 'Internet' }]} />
          </Field>
          <Field label="Data sensitivity">
            <Segmented value={ctx.data_sensitivity} onChange={(v) => setCtx({ ...ctx, data_sensitivity: v })} options={[{ value: 'low', label: 'Low' }, { value: 'medium', label: 'Medium' }, { value: 'high', label: 'High / regulated' }]} />
          </Field>
          <Field label="Expected concurrent users / agents">
            <input type="number" min={1} className={inputCls} value={ctx.expected_concurrency} onChange={(e) => setCtx({ ...ctx, expected_concurrency: Math.max(1, Number(e.target.value) || 1) })} />
          </Field>
        </div>
      </Card>

      <Card title="4 · Analysis">
        <div className="space-y-4">
          <div className={cls('flex flex-wrap items-center justify-between gap-3 rounded-lg p-3', llmReady ? 'bg-brand-50 dark:bg-brand-950/50' : 'bg-amber-50 dark:bg-amber-950/40')}>
            <div className="flex items-center gap-2 text-sm">
              <Sparkles size={16} className={llmReady ? 'text-brand-600' : 'text-amber-600'} />
              {llmReady ? <>LLM review with <b>{health?.llm_model}</b> — tool-by-tool review, false-positive triage, architecture & executive summary.</>
                : <>No LLM configured: the audit will use static analysis only.</>}
            </div>
            {llmReady ? <Toggle checked={useLlm} onChange={setUseLlm} label="Use LLM" /> : <Button size="sm" variant="outline" onClick={onSettings}>Configure LLM</Button>}
          </div>
          {llmReady && useLlm && (
            <Field label="LLM review depth" hint="quick ≈ 8 tools / 8 triages · standard ≈ 25 / 20 · deep ≈ 80 / 60 (also triages medium findings)">
              <Segmented value={depth} onChange={setDepth} options={[{ value: 'quick', label: 'Quick' }, { value: 'standard', label: 'Standard' }, { value: 'deep', label: 'Deep' }]} />
            </Field>
          )}
          <Field label="External scanners (used when installed on the Assay host)">
            <div className="flex flex-wrap gap-2">
              {ALL_SCANNERS.map((n) => {
                const info = scanners.find((s) => s.name === n);
                const on = tools.includes(n);
                return (
                  <button key={n} type="button" onClick={() => setTools(on ? tools.filter((t) => t !== n) : [...tools, n])}
                    className={cls('rounded-md border px-2.5 py-1 text-xs font-medium', on ? 'border-brand-500 bg-brand-50 text-brand-700 dark:bg-brand-950 dark:text-brand-300' : 'border-zinc-300 text-zinc-500 dark:border-zinc-700')}>
                    {n} <span className={info?.available ? 'text-green-600' : 'text-zinc-400'}>{info?.available ? '●' : '○'}</span>
                  </button>
                );
              })}
            </div>
          </Field>
          <Toggle checked={includeTests} onChange={setIncludeTests} label="Also analyse test code" />
        </div>
      </Card>

      <div className="flex justify-end"><Button icon={Play} busy={busy} onClick={submit}>Start audit</Button></div>
      {browsing && <FolderPicker start={location} onClose={() => setBrowsing(false)} onPick={(p) => { setLocation(p); setBrowsing(false); }} />}
    </div>
  );
}

function FolderPicker({ start, onPick, onClose }: { start: string; onPick: (p: string) => void; onClose: () => void }) {
  const [data, setData] = useState<BrowseResult | null>(null);
  const [err, setErr] = useState('');
  const go = (p: string) => api.browse(p).then((d) => { setData(d); setErr(''); }).catch((e) => setErr(e.message));
  useEffect(() => { go(start); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, []);
  return (
    <Modal title="Choose the MCP server folder" onClose={onClose} wide>
      {err && <div className="mb-2 text-sm text-red-600">{err}</div>}
      {data && (
        <>
          <div className="mb-2 flex items-center gap-2">
            <Button size="sm" variant="outline" icon={ArrowUp} disabled={!data.parent} onClick={() => data.parent && go(data.parent)}>Up</Button>
            <code className="truncate text-xs text-zinc-500">{data.path || 'allowed roots'}</code>
          </div>
          <div className="max-h-[50vh] overflow-auto rounded-lg border border-zinc-200 dark:border-zinc-800">
            {data.dirs.map((d) => (
              <button key={d.path} onClick={() => go(d.path)} className="flex w-full items-center gap-2 border-b border-zinc-100 px-3 py-2 text-left text-sm hover:bg-zinc-50 dark:border-zinc-800 dark:hover:bg-zinc-800">
                <Folder size={14} className={d.project ? 'text-brand-600' : 'text-zinc-400'} />{d.name}
                {d.project && <span className="ml-auto text-[10px] uppercase text-brand-600">project</span>}
              </button>
            ))}
            {data.dirs.length === 0 && <div className="p-4 text-sm text-zinc-500">No sub-folder.</div>}
          </div>
          <div className="mt-3 flex justify-end gap-2">
            <Button variant="outline" onClick={onClose}>Cancel</Button>
            <Button disabled={!data.path} onClick={() => onPick(data.path)}>Audit this folder</Button>
          </div>
        </>
      )}
    </Modal>
  );
}
