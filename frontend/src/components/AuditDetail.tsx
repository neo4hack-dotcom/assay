import {
  ArrowLeft, Ban, Bot, CheckCircle2, ChevronDown, ChevronRight, Download, ExternalLink, FileJson, FileText, Gauge as GaugeIcon,
  ListChecks, Presentation, RotateCcw, ScrollText, Search, ShieldCheck, Wrench, XCircle,
} from 'lucide-react';
import { Fragment, useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import type { AuditResult, Dimension, Finding, Severity, StageLog } from '../types';
import {
  Button, Card, DECISION_STYLE, Empty, Field, Gauge, Modal, Pill, Radar, ScoreBar, Segmented, SevBadge, Spinner, cls, fmtDate,
  inputCls, scoreHex, useToast,
} from './ui';

type Tab = 'overview' | 'findings' | 'surface' | 'plan' | 'metrics' | 'log';
const SEVS: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export function AuditDetail({ id, onBack, onOpen }: { id: string; onBack: () => void; onOpen: (id: string) => void }) {
  const [a, setA] = useState<AuditResult | null>(null);
  const [live, setLive] = useState<{ progress: number; stage: string; status: string; logs: StageLog[] } | null>(null);
  const [tab, setTab] = useState<Tab>('overview');
  const [err, setErr] = useState('');
  const toast = useToast();

  const load = useCallback(() => api.audit(id).then(setA).catch((e) => setErr(e.message)), [id]);
  useEffect(() => {
    setA(null); setLive(null); setErr('');
    let t: ReturnType<typeof setInterval> | undefined;
    const poll = async () => {
      try {
        const s = await api.status(id);
        setLive({ progress: s.progress, stage: s.stage, status: s.status, logs: s.logs });
        if (s.status !== 'running' && s.status !== 'queued') { clearInterval(t); load(); }
      } catch (e) { setErr((e as Error).message); clearInterval(t); }
    };
    poll();
    t = setInterval(poll, 1200);
    return () => clearInterval(t);
  }, [id, load]);

  if (err) return <Empty icon={XCircle} title="Audit unavailable">{err}</Empty>;
  if (!a) {
    return (
      <div className="mx-auto max-w-2xl space-y-4">
        <Button variant="ghost" icon={ArrowLeft} onClick={onBack}>Portfolio</Button>
        <Card title="Audit in progress">
          {live ? (
            <div className="space-y-3">
              <div className="flex justify-between text-sm"><span className="font-medium">{live.stage}</span><span>{live.progress}%</span></div>
              <div className="h-2 overflow-hidden rounded-full bg-zinc-200 dark:bg-zinc-800"><div className="h-full bg-brand-600 transition-all" style={{ width: `${live.progress}%` }} /></div>
              <LogList logs={live.logs} />
              <Button variant="outline" size="sm" icon={Ban} onClick={() => api.cancelAudit(id).then(() => toast('Cancellation requested'))}>Cancel</Button>
            </div>
          ) : <Spinner label="Loading…" />}
        </Card>
      </div>
    );
  }

  if (a.status !== 'done' || !a.verdict) {
    return (
      <div className="mx-auto max-w-3xl space-y-4">
        <Button variant="ghost" icon={ArrowLeft} onClick={onBack}>Portfolio</Button>
        <Card title={`${a.project} — ${a.status}`}>
          {a.error && <div className="mb-3 rounded-lg bg-red-50 p-3 text-sm text-red-800 dark:bg-red-950 dark:text-red-200">{a.error}</div>}
          <LogList logs={a.logs} />
        </Card>
      </div>
    );
  }

  const v = a.verdict;
  const open = a.findings.filter((f) => f.status === 'open');
  const tabs: { id: Tab; label: string; icon: typeof ListChecks; count?: number }[] = [
    { id: 'overview', label: 'Overview', icon: GaugeIcon }, { id: 'findings', label: 'Findings', icon: Search, count: open.length },
    { id: 'surface', label: 'MCP surface', icon: Wrench, count: a.server.tools.length }, { id: 'plan', label: 'Action plan', icon: ListChecks, count: a.actions.length },
    { id: 'metrics', label: 'Sustainability', icon: ShieldCheck }, { id: 'log', label: 'Log & coverage', icon: ScrollText },
  ];

  return (
    <div className="space-y-5">
      <Button variant="ghost" icon={ArrowLeft} onClick={onBack}>Portfolio</Button>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="truncate text-2xl font-bold">{a.project}</h1>
            <span className={cls('rounded-md px-2.5 py-1 text-sm font-bold', DECISION_STYLE[v.decision])}>{v.label}</span>
          </div>
          <div className="mt-1 text-sm text-zinc-500">
            {fmtDate(a.finished_at)} · {a.source.kind}: {a.source.location}{a.commit && ` @${a.commit}`} · {a.options.context.deployment}, {a.options.context.exposure}
            {a.llm_model && <> · <Bot size={12} className="inline" /> {a.llm_model}</>}
          </div>
        </div>
        <Downloads a={a} onRerun={async () => { try { const b = await api.rerun(a.id); onOpen(b.id); } catch (e) { toast((e as Error).message, 'error'); } }} />
      </div>

      <div className="flex gap-1 overflow-x-auto border-b border-zinc-200 dark:border-zinc-800">
        {tabs.map(({ id: t, label, icon: Icon, count }) => (
          <button key={t} onClick={() => setTab(t)}
            className={cls('inline-flex shrink-0 items-center gap-1.5 border-b-2 px-3 py-2 text-sm font-medium',
              tab === t ? 'border-brand-600 text-brand-700 dark:text-brand-300' : 'border-transparent text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200')}>
            <Icon size={15} />{label}{count != null && <span className="rounded-full bg-zinc-100 px-1.5 text-[11px] dark:bg-zinc-800">{count}</span>}
          </button>
        ))}
      </div>

      {tab === 'overview' && <Overview a={a} onJump={() => setTab('findings')} />}
      {tab === 'findings' && <Findings a={a} onChanged={load} />}
      {tab === 'surface' && <Surface a={a} />}
      {tab === 'plan' && <Plan a={a} />}
      {tab === 'metrics' && <MetricsView a={a} />}
      {tab === 'log' && <Coverage a={a} />}
    </div>
  );
}

function Downloads({ a, onRerun }: { a: AuditResult; onRerun: () => void }) {
  const [busy, setBusy] = useState('');
  const toast = useToast();
  const dl = async (fmt: string) => {
    setBusy(fmt);
    try { if (fmt === 'view') await api.openHtml(a.id); else await api.download(a.id, fmt); } catch (e) { toast((e as Error).message, 'error'); } finally { setBusy(''); }
  };
  return (
    <div className="flex flex-wrap gap-2">
      <Button icon={FileText} busy={busy === 'pdf'} onClick={() => dl('pdf')}>PDF</Button>
      <Button icon={Presentation} busy={busy === 'pptx'} onClick={() => dl('pptx')}>PowerPoint</Button>
      <Button variant="outline" icon={ExternalLink} busy={busy === 'view'} onClick={() => dl('view')}>HTML</Button>
      <Button variant="outline" icon={Download} busy={busy === 'md'} onClick={() => dl('md')}>Markdown</Button>
      <Button variant="outline" icon={FileJson} busy={busy === 'sarif'} onClick={() => dl('sarif')}>SARIF</Button>
      <Button variant="outline" icon={FileJson} busy={busy === 'json'} onClick={() => dl('json')}>JSON</Button>
      {a.source.kind !== 'zip' && <Button variant="ghost" icon={RotateCcw} onClick={onRerun}>Re-audit</Button>}
    </div>
  );
}

// ------------------------------------------------------------------ overview
function Overview({ a, onJump }: { a: AuditResult; onJump: () => void }) {
  const v = a.verdict!;
  const counts = SEVS.map((s) => [s, a.findings.filter((f) => f.status === 'open' && f.severity === s).length] as const);
  return (
    <div className="space-y-5">
      <div className="grid gap-4 lg:grid-cols-[auto_auto_1fr]">
        <Card><div className="flex justify-center"><Gauge value={v.readiness} label="production readiness" /></div>
          <div className="text-center text-xs text-zinc-500">raw weighted {v.raw_weighted}% · confidence <b>{v.confidence}</b></div></Card>
        <Card><div className="flex justify-center"><Gauge value={v.sustainability} label="sustainability" color="#4f46e5" /></div>
          <div className="text-center text-xs text-zinc-500">long-term maintainability outlook</div></Card>
        <Card title="Open findings" actions={<Button size="sm" variant="ghost" onClick={onJump}>View all</Button>}>
          <div className="space-y-2">
            {counts.map(([s, n]) => (
              <div key={s} className="flex items-center gap-3">
                <SevBadge sev={s} className="w-16 justify-center" />
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800">
                  <div className="h-full" style={{ width: `${Math.min(100, n * 6)}%`, background: { critical: '#b91c1c', high: '#ea580c', medium: '#d97706', low: '#2563eb', info: '#71717a' }[s] }} />
                </div>
                <span className="w-8 text-right text-sm font-semibold">{n}</span>
              </div>
            ))}
          </div>
          {a.comparison && <div className="mt-3 text-xs text-zinc-500">vs previous audit ({a.comparison.previous_readiness}%): <b className="text-green-700">{a.comparison.fixed} fixed</b> · <b className="text-red-700">{a.comparison.new} new</b> · {a.comparison.persisting} persisting</div>}
        </Card>
      </div>

      {v.gates.length > 0 && (
        <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-900 dark:border-red-900 dark:bg-red-950/50 dark:text-red-200">
          <b>Decision gates applied.</b> {v.gates.join(' ')}
        </div>
      )}

      <div className="grid gap-5 lg:grid-cols-[1fr_320px]">
        <Card title={<span>Executive summary <span className="ml-1 text-xs font-normal text-zinc-500">({a.narrative.generated_by === 'rules' ? 'rules-based' : `by ${a.narrative.generated_by}`})</span></span>}>
          <div className="space-y-3 text-sm leading-relaxed">{a.narrative.executive_summary.split('\n\n').map((p, i) => <p key={i}>{p}</p>)}</div>
        </Card>
        <Card title="Scorecard">
          <div className="flex justify-center"><Radar items={a.scores.map((s) => ({ label: s.label, value: s.score }))} size={240} /></div>
          <div className="mt-2 space-y-2">
            {a.scores.map((s) => (
              <div key={s.dimension}>
                <div className="flex justify-between text-xs"><span>{s.label}</span><b style={{ color: scoreHex(s.score) }}>{s.score} {s.grade}</b></div>
                <ScoreBar score={s.score} />
              </div>
            ))}
          </div>
        </Card>
      </div>

      <div className="grid gap-5 md:grid-cols-3">
        <Card title="Key risks"><ul className="list-disc space-y-1.5 pl-4 text-sm">{(a.narrative.key_risks.length ? a.narrative.key_risks : ['None identified.']).map((r, i) => <li key={i}>{r}</li>)}</ul></Card>
        <Card title="Strengths"><ul className="list-disc space-y-1.5 pl-4 text-sm">{(a.narrative.strengths.length ? a.narrative.strengths : ['No notable control detected.']).map((r, i) => <li key={i}>{r}</li>)}</ul></Card>
        <Card title="Conditions before go-live"><ul className="list-disc space-y-1.5 pl-4 text-sm">{(a.narrative.conditions.length ? a.narrative.conditions : ['No blocking condition.']).map((r, i) => <li key={i}>{r}</li>)}</ul></Card>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        {([['Architecture', a.narrative.architecture], ['Security', a.narrative.security], ['Scalability', a.narrative.scalability],
          ['Performance & token efficiency', a.narrative.performance], ['Sustainability', a.narrative.sustainability]] as const).map(([t, txt]) => txt && (
          <Card key={t} title={t}><div className="space-y-2 text-sm leading-relaxed text-zinc-700 dark:text-zinc-300">{txt.split('\n\n').map((p, i) => <p key={i}>{p}</p>)}</div></Card>
        ))}
      </div>
      {v.confidence_reasons.length > 0 && <p className="text-xs text-zinc-500">Confidence limits: {v.confidence_reasons.join(' ')}</p>}
    </div>
  );
}

// ------------------------------------------------------------------ findings
function Findings({ a, onChanged }: { a: AuditResult; onChanged: () => void }) {
  const [sev, setSev] = useState<Severity | 'all'>('all');
  const [dim, setDim] = useState<Dimension | 'all'>('all');
  const [status, setStatus] = useState<'open' | 'closed' | 'all'>('open');
  const [q, setQ] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [triage, setTriage] = useState<Finding | null>(null);
  const list = useMemo(() => a.findings.filter((f) =>
    (sev === 'all' || f.severity === sev) && (dim === 'all' || f.dimension === dim) &&
    (status === 'all' || (status === 'open' ? f.status === 'open' : f.status !== 'open')) &&
    (!q || `${f.title} ${f.message} ${f.file} ${f.rule_id} ${f.tool}`.toLowerCase().includes(q.toLowerCase()))), [a, sev, dim, status, q]);
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative"><Search size={14} className="absolute left-2.5 top-2.5 text-zinc-400" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search title, file, tool, rule…" className={cls(inputCls, 'w-64 pl-8')} /></div>
        <select className={cls(inputCls, 'w-36')} value={sev} onChange={(e) => setSev(e.target.value as Severity | 'all')}>
          <option value="all">All severities</option>{SEVS.map((s) => <option key={s} value={s}>{s}</option>)}</select>
        <select className={cls(inputCls, 'w-44')} value={dim} onChange={(e) => setDim(e.target.value as Dimension | 'all')}>
          <option value="all">All dimensions</option>{a.scores.map((s) => <option key={s.dimension} value={s.dimension}>{s.label}</option>)}</select>
        <Segmented value={status} onChange={setStatus} options={[{ value: 'open', label: 'Open' }, { value: 'closed', label: 'Triaged' }, { value: 'all', label: 'All' }]} />
        <span className="text-sm text-zinc-500">{list.length} finding(s)</span>
      </div>
      {list.length === 0 && <Empty icon={CheckCircle2} title="Nothing matches these filters" />}
      <div className="space-y-2">
        {list.map((f, i) => {
          const key = `${f.fingerprint}-${i}`;
          const isOpen = expanded === key;
          return (
            <div key={key} className={cls('rounded-xl border bg-white dark:bg-zinc-900', f.status !== 'open' ? 'border-zinc-200 opacity-70 dark:border-zinc-800' : 'border-zinc-200 dark:border-zinc-800')}>
              <button className="flex w-full items-start gap-3 px-4 py-3 text-left" onClick={() => setExpanded(isOpen ? null : key)}>
                {isOpen ? <ChevronDown size={16} className="mt-0.5 shrink-0" /> : <ChevronRight size={16} className="mt-0.5 shrink-0" />}
                <SevBadge sev={f.severity} className="mt-0.5 shrink-0" />
                <div className="min-w-0 flex-1">
                  <div className="font-medium">{f.title} <span className="text-xs font-normal text-zinc-500">{f.rule_id}</span></div>
                  <div className="truncate text-xs text-zinc-500">{f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : 'project-wide'}{f.tool && ` · tool ${f.tool}`} · {f.message}</div>
                </div>
                <div className="hidden shrink-0 flex-col items-end gap-1 sm:flex">
                  <Pill tone={f.confidence === 'high' ? 'brand' : 'zinc'}>{f.confidence}</Pill>
                  {f.llm && <Pill tone={f.llm.verdict === 'false_positive' ? 'amber' : f.llm.verdict === 'true_positive' ? 'red' : 'zinc'}><Bot size={11} />{f.llm.verdict.replace('_', ' ')}</Pill>}
                  {f.status !== 'open' && <Pill tone="green">{f.status.replace('_', ' ')}</Pill>}
                </div>
              </button>
              {isOpen && (
                <div className="space-y-3 border-t border-zinc-100 px-4 py-3 text-sm dark:border-zinc-800">
                  {f.message && <p>{f.message}</p>}
                  {f.snippet && <pre className="overflow-x-auto rounded-lg bg-zinc-950 p-3 font-mono text-xs text-zinc-100">{f.snippet}</pre>}
                  {f.impact && <p><b>Impact.</b> {f.impact}</p>}
                  {f.remediation && <p><b>Remediation.</b> {f.remediation}</p>}
                  {f.llm && <p className="rounded-lg bg-zinc-50 p-2 text-xs dark:bg-zinc-800"><b>LLM triage ({f.llm.model}):</b> {f.llm.verdict.replace('_', ' ')} — {f.llm.rationale}</p>}
                  {f.context_note && <p className="text-xs text-zinc-500"><b>Context:</b> {f.context_note}</p>}
                  {f.status_reason && <p className="text-xs text-green-700 dark:text-green-400"><b>Triage:</b> {f.status_reason}</p>}
                  <div className="flex flex-wrap gap-1.5 text-xs">
                    {[...f.standards.owasp_mcp, ...f.standards.owasp_llm, ...f.standards.cwe, ...f.standards.mcp_spec].map((s) => <Pill key={s}>{s}</Pill>)}
                    <Pill>source {f.source}</Pill><Pill>effort {f.effort}</Pill>
                  </div>
                  {f.references.length > 0 && <div className="flex flex-wrap gap-3 text-xs">{f.references.map((r) => r.url && <a key={r.url} href={r.url} target="_blank" rel="noreferrer" className="text-brand-600 hover:underline">{r.label}</a>)}</div>}
                  <div className="flex gap-2">
                    {f.status === 'open' ? <Button size="sm" variant="outline" onClick={() => setTriage(f)}>Accept risk / mark false positive</Button>
                      : f.status !== 'suppressed_inline' && <Button size="sm" variant="outline" onClick={async () => { await api.triage(a.id, f.fingerprint, { status: 'open', reason: '', by: '', remember: true }); onChanged(); }}>Re-open</Button>}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
      {triage && <TriageModal a={a} f={triage} onClose={() => setTriage(null)} onDone={() => { setTriage(null); onChanged(); }} />}
    </div>
  );
}

function TriageModal({ a, f, onClose, onDone }: { a: AuditResult; f: Finding; onClose: () => void; onDone: () => void }) {
  const [status, setStatus] = useState<'accepted' | 'false_positive'>('false_positive');
  const [reason, setReason] = useState('');
  const [by, setBy] = useState(() => { try { return localStorage.getItem('assay-reviewer') ?? ''; } catch { return ''; } });
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const save = async () => {
    setBusy(true);
    try {
      try { localStorage.setItem('assay-reviewer', by); } catch { /* ignore */ }
      await api.triage(a.id, f.fingerprint, { status, reason, by, remember: true });
      toast('Finding triaged — scores recomputed');
      onDone();
    } catch (e) { toast((e as Error).message, 'error'); } finally { setBusy(false); }
  };
  return (
    <Modal title="Triage finding" onClose={onClose}>
      <div className="space-y-4 text-sm">
        <div><SevBadge sev={f.severity} /> <b>{f.title}</b><div className="text-xs text-zinc-500">{f.file}:{f.line}</div></div>
        <Segmented value={status} onChange={setStatus} options={[{ value: 'false_positive', label: 'False positive' }, { value: 'accepted', label: 'Accepted risk' }]} />
        <Field label="Justification (kept in the report and reused by future audits of this project)">
          <textarea className={cls(inputCls, 'h-24')} value={reason} onChange={(e) => setReason(e.target.value)}
            placeholder={status === 'accepted' ? 'e.g. Authentication enforced by the API gateway (policy GW-12), see ticket SEC-481' : 'e.g. Value is a constant from the config schema'} />
        </Field>
        <Field label="Reviewer"><input className={inputCls} value={by} onChange={(e) => setBy(e.target.value)} placeholder="name or team" /></Field>
        <div className="flex justify-end gap-2"><Button variant="outline" onClick={onClose}>Cancel</Button><Button busy={busy} disabled={reason.trim().length < 5} onClick={save}>Save</Button></div>
      </div>
    </Modal>
  );
}

// ------------------------------------------------------------------ surface
const SIGNALS: [string, string][] = [
  ['rate_limit', 'Rate limiting'], ['concurrency_limit', 'Concurrency limits'], ['pooling', 'Connection pooling'], ['async_io', 'Async I/O'],
  ['cache', 'Caching'], ['retry', 'Retry / backoff'], ['timeouts', 'Timeouts'], ['health', 'Health endpoint'], ['graceful_shutdown', 'Graceful shutdown'],
  ['logging', 'Logging'], ['structured_logging', 'Structured logs'], ['metrics_tracing', 'Metrics / tracing'], ['audit_log', 'Audit trail'],
  ['input_validation', 'Schema validation'], ['dns_rebinding', 'Origin / DNS-rebinding'], ['human_confirmation', 'Human confirmation'],
];

function Surface({ a }: { a: AuditResult }) {
  const s = a.server;
  const [sel, setSel] = useState<string | null>(null);
  const tools = [...s.tools].sort((x, y) => SEVS.indexOf(x.risk) - SEVS.indexOf(y.risk));
  return (
    <div className="space-y-5">
      <div className="grid gap-4 md:grid-cols-4">
        <Info label="SDK" value={s.sdks.join(', ') || 'not recognised'} sub={Object.entries(s.sdk_versions).map(([k, x]) => `${k} ${x}`).join(' · ')} />
        <Info label="Transports" value={s.transports.join(', ') || '—'} sub={s.transports.some((t) => t !== 'stdio') ? `session mode: ${s.stateless_http ? 'stateless' : s.stateless_http === false ? 'stateful' : 'default'}` : ''} />
        <Info label="Authentication" value={s.auth.detected ? 'Detected' : 'Not detected'} tone={s.auth.detected ? 'green' : 'red'} sub={s.auth.mechanisms.join(', ')} />
        <Info label="Primitives" value={`${s.tools.filter((t) => t.kind === 'tool').length} tools`} sub={`${s.tools.filter((t) => t.kind === 'resource').length} resources · ${s.tools.filter((t) => t.kind === 'prompt').length} prompts`} />
      </div>
      <Card title="Tools, resources & prompts">
        {tools.length === 0 ? <Empty icon={Wrench} title="No MCP primitive detected" /> : (
          <div className="-mx-4 overflow-x-auto">
            <table className="w-full min-w-[760px] text-sm">
              <thead><tr className="border-b border-zinc-200 text-left text-xs uppercase text-zinc-500 dark:border-zinc-800">
                <th className="px-4 py-2">Name</th><th className="px-2">Risk</th><th className="px-2">Capabilities</th><th className="px-2">Annotations</th><th className="px-2">Params</th><th className="px-2">Description</th></tr></thead>
              <tbody>
                {tools.map((t) => (
                  <Fragment key={`${t.name}-${t.file}-${t.line}`}>
                    <tr className="cursor-pointer border-b border-zinc-100 hover:bg-zinc-50 dark:border-zinc-800/70 dark:hover:bg-zinc-800/40" onClick={() => setSel(sel === `${t.name}${t.line}` ? null : `${t.name}${t.line}`)}>
                      <td className="px-4 py-2"><div className="font-mono text-xs font-semibold">{t.name}</div><div className="text-[11px] text-zinc-500">{t.kind} · {t.file}:{t.line}</div></td>
                      <td className="px-2"><SevBadge sev={t.risk} /></td>
                      <td className="px-2 text-xs">{t.capabilities.join(', ') || '—'}</td>
                      <td className="px-2 text-xs">{Object.entries(t.annotations).filter(([k]) => k.endsWith('Hint')).map(([k, x]) => `${k.replace('Hint', '')}=${x ? 'Y' : 'N'}`).join(' ') || <span className="text-red-600">none</span>}</td>
                      <td className="px-2 text-xs">{t.params.length} ({t.params.filter((p) => p.constrained).length} constrained)</td>
                      <td className="max-w-xs truncate px-2 text-xs text-zinc-600 dark:text-zinc-400">{t.description || <span className="text-red-600">no description</span>}</td>
                    </tr>
                    {sel === `${t.name}${t.line}` && (
                      <tr className="bg-zinc-50 dark:bg-zinc-900/60"><td colSpan={6} className="px-4 py-3 text-xs">
                        {t.llm_review?.summary && <p className="mb-2"><Bot size={12} className="inline" /> <b>LLM review:</b> {t.llm_review.summary} (description {t.llm_review.description_quality})</p>}
                        <p className="mb-2 whitespace-pre-wrap">{t.description}</p>
                        {t.risk_reasons.length > 0 && <p className="mb-2 text-zinc-500">Risk: {t.risk_reasons.join('; ')}</p>}
                        <div className="flex flex-wrap gap-1.5">{t.params.map((p) => <Pill key={p.name} tone={p.constrained ? 'green' : 'amber'}>{p.name}: {p.type}{p.required ? '' : '?'}</Pill>)}</div>
                      </td></tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <Card title="Capacity, resilience & governance controls detected">
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {SIGNALS.map(([k, label]) => {
            const ok = k in s.signals;
            return (
              <div key={k} className="flex items-center gap-2 text-sm" title={(s.signals[k] ?? []).join('\n')}>
                {ok ? <CheckCircle2 size={15} className="text-green-600" /> : <XCircle size={15} className="text-red-500" />}{label}
              </div>
            );
          })}
        </div>
      </Card>
    </div>
  );
}

function Info({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone?: 'green' | 'red' }) {
  return (
    <div className="rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900">
      <div className="text-xs uppercase tracking-wide text-zinc-500">{label}</div>
      <div className={cls('mt-1 font-semibold', tone === 'green' && 'text-green-700 dark:text-green-400', tone === 'red' && 'text-red-700 dark:text-red-400')}>{value}</div>
      {sub && <div className="mt-0.5 text-xs text-zinc-500">{sub}</div>}
    </div>
  );
}

// ------------------------------------------------------------------ plan
function Plan({ a }: { a: AuditResult }) {
  const groups = (['P0', 'P1', 'P2', 'P3'] as const).map((p) => [p, a.actions.filter((x) => x.priority === p)] as const);
  const color = { P0: 'bg-red-700', P1: 'bg-orange-600', P2: 'bg-amber-500', P3: 'bg-blue-600' };
  if (!a.actions.length) return <Empty icon={CheckCircle2} title="No remediation needed" />;
  return (
    <div className="space-y-5">
      {groups.map(([p, items]) => items.length > 0 && (
        <Card key={p} title={<span className="inline-flex items-center gap-2"><span className={cls('rounded px-1.5 py-0.5 text-xs text-white', color[p])}>{p}</span>{items[0].horizon} · {items.length} action(s)</span>}>
          <div className="divide-y divide-zinc-100 dark:divide-zinc-800">
            {items.map((it) => (
              <div key={it.rule_id} className="grid gap-2 py-3 md:grid-cols-[1fr_1.4fr]">
                <div>
                  <div className="flex items-center gap-2"><SevBadge sev={it.severity} /><b className="text-sm">{it.title}</b></div>
                  <div className="mt-1 text-xs text-zinc-500">{it.rule_id} · {it.occurrences} occurrence(s) · effort {it.effort} · {it.dimension}</div>
                  <div className="mt-1 truncate text-xs text-zinc-500">{it.locations.slice(0, 4).join(', ')}</div>
                </div>
                <p className="text-sm text-zinc-700 dark:text-zinc-300">{it.remediation}</p>
              </div>
            ))}
          </div>
        </Card>
      ))}
    </div>
  );
}

// ------------------------------------------------------------------ metrics
function MetricsView({ a }: { a: AuditResult }) {
  const m = a.metrics;
  const tiles: [string, string][] = [
    ['Sustainability', `${a.verdict!.sustainability}%`], ['Production LOC', m.loc_total.toLocaleString()], ['Test files / ratio', `${m.test_files} / ${m.test_ratio.toFixed(2)}`],
    ['Avg. / max complexity', `${m.avg_complexity} / ${m.max_complexity}`], ['Complex functions', String(m.complex_functions)],
    ['Dependencies (pinned)', `${m.dependencies} (${m.dependencies_pinned_pct ?? '—'}%)`], ['Typed Python functions', m.typed_functions_pct != null ? `${m.typed_functions_pct}%` : 'n/a'],
    ['TODO / FIXME', String(m.todo_count)],
  ];
  const checks: [string, boolean][] = [['Automated tests', m.test_files > 0], ['CI pipeline', m.has_ci], ['Lockfile', m.lockfiles.length > 0], ['README', m.has_readme],
    ['Container image', m.has_dockerfile], ['Changelog', m.has_changelog], ['License', m.has_license]];
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {tiles.map(([k, x]) => <div key={k} className="rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900"><div className="text-xs text-zinc-500">{k}</div><div className="mt-1 text-xl font-bold">{x}</div></div>)}
      </div>
      <div className="grid gap-5 lg:grid-cols-2">
        <Card title="Repository hygiene">
          <div className="grid grid-cols-2 gap-2">{checks.map(([k, ok]) => <div key={k} className="flex items-center gap-2 text-sm">{ok ? <CheckCircle2 size={15} className="text-green-600" /> : <XCircle size={15} className="text-red-500" />}{k}</div>)}</div>
          {m.ci_systems.length > 0 && <p className="mt-3 text-xs text-zinc-500">CI: {m.ci_systems.join(', ')}</p>}
          {Object.keys(m.git).length > 0 && <p className="mt-2 text-xs text-zinc-500">Git: {String(m.git.commits)} commits · {String(m.git.contributors)} contributor(s) · top contributor {Math.round(Number(m.git.top_contributor_share) * 100)}% · last commit {String(m.git.last_commit_days)} days ago{m.git.shallow ? ' (shallow clone)' : ''}</p>}
          <p className="mt-2 text-xs text-zinc-500">Languages: {Object.entries(m.loc_by_language).map(([k, x]) => `${k} ${x.toLocaleString()}`).join(' · ')}</p>
        </Card>
        <Card title="Complexity hotspots">
          {m.hotspots.length === 0 ? <p className="text-sm text-zinc-500">No function above the complexity threshold.</p> : (
            <table className="w-full text-sm"><thead><tr className="text-left text-xs text-zinc-500"><th>Function</th><th>CCN</th><th>NLOC</th></tr></thead>
              <tbody>{m.hotspots.slice(0, 10).map((h) => <tr key={`${h.file}${h.line}`} className="border-t border-zinc-100 dark:border-zinc-800"><td className="py-1.5"><div className="font-mono text-xs">{h.function}</div><div className="text-[11px] text-zinc-500">{h.file}:{h.line}</div></td><td className="font-semibold">{h.ccn}</td><td>{h.nloc}</td></tr>)}</tbody></table>
          )}
        </Card>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ coverage & log
function Coverage({ a }: { a: AuditResult }) {
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Card title="Analysis coverage">
        <table className="w-full text-sm"><tbody>
          <tr className="border-b border-zinc-100 dark:border-zinc-800"><td className="py-1.5">Assay built-in rules</td><td><Pill tone="green">ok</Pill></td><td className="text-xs text-zinc-500">{a.metrics.files_analyzed} files</td></tr>
          {a.scanners.map((s) => (
            <tr key={s.name} className="border-b border-zinc-100 dark:border-zinc-800"><td className="py-1.5">{s.name}</td>
              <td><Pill tone={s.status === 'ok' ? 'green' : s.status === 'error' ? 'red' : 'zinc'}>{s.status}</Pill></td>
              <td className="text-xs text-zinc-500">{s.status === 'ok' ? `${s.findings} new · ${s.duration_s}s` : s.detail}</td></tr>
          ))}
          <tr><td className="py-1.5">LLM review</td><td><Pill tone={a.llm_model ? 'green' : 'zinc'}>{a.llm_model ? 'ok' : 'not used'}</Pill></td><td className="text-xs text-zinc-500">{a.llm_model}</td></tr>
        </tbody></table>
        <p className="mt-3 text-xs text-zinc-500">Documentation used: {a.docs_used.join(', ') || 'none'}</p>
      </Card>
      <Card title="Execution log"><LogList logs={a.logs} /></Card>
    </div>
  );
}

function LogList({ logs }: { logs: StageLog[] }) {
  return (
    <div className="max-h-80 overflow-auto rounded-lg bg-zinc-950 p-3 font-mono text-[11px] leading-relaxed text-zinc-300">
      {logs.map((l, i) => (
        <div key={i} className={cls(l.level === 'error' && 'text-red-400', l.level === 'warning' && 'text-amber-300')}>
          <span className="text-zinc-500">{new Date(l.ts * 1000).toLocaleTimeString()}</span> {l.message.split('\n').slice(-3).join(' ')}
        </div>
      ))}
      {logs.length === 0 && <span className="text-zinc-500">No log yet.</span>}
    </div>
  );
}
