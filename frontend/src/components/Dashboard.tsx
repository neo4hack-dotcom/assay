import { Activity, AlertOctagon, CheckCircle2, FolderSearch, Loader2, Plus, RotateCcw, ShieldAlert, Trash2, XCircle } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import type { AuditSummary, Dimension } from '../types';
import { Button, Card, DECISION_STYLE, Empty, Pill, ScoreBar, Segmented, Spinner, cls, fmtDate, scoreHex, useConfirm, useToast } from './ui';

const DIMS: { id: Dimension; short: string }[] = [
  { id: 'security', short: 'Sec' }, { id: 'scalability', short: 'Scal' }, { id: 'performance', short: 'Perf' },
  { id: 'reliability', short: 'Rel' }, { id: 'observability', short: 'Obs' }, { id: 'maintainability', short: 'Maint' },
];

export function Dashboard({ onOpen, onNew }: { onOpen: (id: string) => void; onNew: () => void }) {
  const [audits, setAudits] = useState<AuditSummary[] | null>(null);
  const [view, setView] = useState<'portfolio' | 'history'>('portfolio');
  const [q, setQ] = useState('');
  const toast = useToast();
  const confirm = useConfirm();

  const load = () => api.audits().then(setAudits).catch((e) => toast(String(e.message), 'error'));
  useEffect(() => {
    load();
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const portfolio = useMemo(() => {
    const latest = new Map<string, AuditSummary>();
    for (const a of audits ?? []) {
      if (a.status !== 'done') continue;
      const cur = latest.get(a.project);
      if (!cur || a.created_at > cur.created_at) latest.set(a.project, a);
    }
    return [...latest.values()].sort((a, b) => (a.readiness ?? 0) - (b.readiness ?? 0));
  }, [audits]);

  if (audits === null) return <Spinner label="Loading audits…" />;
  const running = audits.filter((a) => a.status === 'running' || a.status === 'queued');
  const rows = (view === 'portfolio' ? portfolio : audits).filter((a) => !q || a.project.toLowerCase().includes(q.toLowerCase()));
  const avg = portfolio.length ? Math.round(portfolio.reduce((s, a) => s + (a.readiness ?? 0), 0) / portfolio.length) : 0;
  const goCount = portfolio.filter((a) => a.decision === 'GO').length;
  const condCount = portfolio.filter((a) => a.decision === 'GO_WITH_CONDITIONS').length;
  const crit = portfolio.reduce((s, a) => s + a.counts.critical, 0);

  const del = async (a: AuditSummary) => {
    if (!(await confirm(`Delete the audit of "${a.project}" from ${fmtDate(a.created_at)}? Reports are deleted too.`, true))) return;
    await api.deleteAudit(a.id).then(load).catch((e) => toast(e.message, 'error'));
  };
  const rerun = async (a: AuditSummary) => {
    try { const b = await api.rerun(a.id); toast(`Re-audit of ${a.project} started`); onOpen(b.id); } catch (e) { toast((e as Error).message, 'error'); }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">MCP portfolio</h1>
          <p className="text-sm text-zinc-500">Production readiness of every MCP server audited in your organisation.</p>
        </div>
        <Button icon={Plus} onClick={onNew}>New audit</Button>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Kpi icon={FolderSearch} label="MCP servers audited" value={String(portfolio.length)} />
        <Kpi icon={Activity} label="Average readiness" value={portfolio.length ? `${avg}%` : '—'} color={portfolio.length ? scoreHex(avg) : undefined} />
        <Kpi icon={CheckCircle2} label="Go / with conditions" value={`${goCount} / ${condCount}`} />
        <Kpi icon={ShieldAlert} label="Open critical findings" value={String(crit)} color={crit ? '#b91c1c' : '#15803d'} />
      </div>

      {running.length > 0 && (
        <Card title={<span className="inline-flex items-center gap-2"><Loader2 size={14} className="animate-spin" /> In progress</span>}>
          <div className="space-y-3">
            {running.map((a) => (
              <button key={a.id} onClick={() => onOpen(a.id)} className="block w-full text-left">
                <div className="mb-1 flex justify-between text-sm"><span className="font-medium">{a.project}</span><span className="text-zinc-500">{a.stage} · {a.progress}%</span></div>
                <div className="h-1.5 overflow-hidden rounded-full bg-zinc-200 dark:bg-zinc-800"><div className="h-full bg-brand-600 transition-all" style={{ width: `${a.progress}%` }} /></div>
              </button>
            ))}
          </div>
        </Card>
      )}

      <Card title={view === 'portfolio' ? 'Latest audit per MCP server (weakest first)' : 'All audits'}
        actions={<>
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter…" className="w-36 rounded-md border border-zinc-300 bg-white px-2 py-1 text-xs dark:border-zinc-700 dark:bg-zinc-950" />
          <Segmented value={view} onChange={setView} options={[{ value: 'portfolio', label: 'Portfolio' }, { value: 'history', label: 'History' }]} />
        </>}>
        {rows.length === 0 ? (
          <Empty icon={FolderSearch} title="No audit yet">Start with <b>New audit</b>: point Assay at a folder, a git repository or a ZIP of an MCP server.</Empty>
        ) : (
          <div className="-mx-4 overflow-x-auto">
            <table className="w-full min-w-[860px] text-sm">
              <thead>
                <tr className="border-b border-zinc-200 text-left text-xs uppercase tracking-wide text-zinc-500 dark:border-zinc-800">
                  <th className="px-4 py-2">MCP server</th><th className="px-2 py-2">Decision</th><th className="px-2 py-2">Readiness</th>
                  <th className="px-2 py-2">Sustain.</th>
                  {DIMS.map((d) => <th key={d.id} className="px-1 py-2 text-center">{d.short}</th>)}
                  <th className="px-2 py-2">Crit/High</th><th className="px-2 py-2">Date</th><th className="px-2 py-2" />
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => (
                  <tr key={a.id} className="cursor-pointer border-b border-zinc-100 hover:bg-zinc-50 dark:border-zinc-800/70 dark:hover:bg-zinc-800/40" onClick={() => onOpen(a.id)}>
                    <td className="px-4 py-2.5">
                      <div className="font-medium">{a.project}</div>
                      <div className="max-w-[260px] truncate text-xs text-zinc-500">{a.source.kind}: {a.source.location}{a.commit ? ` @${a.commit}` : ''}</div>
                    </td>
                    <td className="px-2 py-2.5">
                      {a.status === 'done' && a.decision ? <span className={cls('rounded px-2 py-0.5 text-xs font-semibold', DECISION_STYLE[a.decision])}>{a.label}</span>
                        : a.status === 'failed' ? <Pill tone="red"><XCircle size={12} />failed</Pill>
                          : a.status === 'cancelled' ? <Pill>cancelled</Pill> : <Pill tone="brand"><Loader2 size={12} className="animate-spin" />{a.progress}%</Pill>}
                    </td>
                    <td className="px-2 py-2.5">{a.readiness != null ? (
                      <div className="w-28"><div className="mb-0.5 text-sm font-bold" style={{ color: scoreHex(a.readiness) }}>{a.readiness}%</div><ScoreBar score={a.readiness} /></div>) : '—'}</td>
                    <td className="px-2 py-2.5 text-sm font-semibold">{a.sustainability != null ? `${a.sustainability}%` : '—'}</td>
                    {DIMS.map((d) => {
                      const s = a.scores[d.id];
                      return <td key={d.id} className="px-1 py-2.5 text-center">{s != null ? <span className="inline-block min-w-[2.2rem] rounded px-1 py-0.5 text-xs font-bold text-white" style={{ background: scoreHex(s) }}>{s}</span> : '—'}</td>;
                    })}
                    <td className="px-2 py-2.5 text-xs">
                      {a.status === 'done' ? <><span className={a.counts.critical ? 'font-bold text-red-700 dark:text-red-400' : 'text-zinc-500'}>{a.counts.critical}</span> / <span className={a.counts.high ? 'font-semibold text-orange-600' : 'text-zinc-500'}>{a.counts.high}</span></> : '—'}
                      {a.comparison && <div className="text-[10px] text-zinc-500">{a.comparison.fixed} fixed · {a.comparison.new} new</div>}
                    </td>
                    <td className="px-2 py-2.5 text-xs text-zinc-500">{fmtDate(a.created_at)}</td>
                    <td className="px-2 py-2.5" onClick={(e) => e.stopPropagation()}>
                      <div className="flex gap-1">
                        {a.source.kind !== 'zip' && a.status !== 'running' && <button title="Re-audit" onClick={() => rerun(a)} className="rounded p-1.5 text-zinc-500 hover:bg-zinc-100 dark:hover:bg-zinc-800"><RotateCcw size={14} /></button>}
                        <button title="Delete" onClick={() => del(a)} className="rounded p-1.5 text-zinc-500 hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-950"><Trash2 size={14} /></button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {view === 'history' && audits.some((a) => a.status === 'failed') && (
          <p className="mt-3 flex items-center gap-1 text-xs text-zinc-500"><AlertOctagon size={12} /> Open a failed audit to see why it stopped.</p>
        )}
      </Card>
    </div>
  );
}

function Kpi({ icon: Icon, label, value, color }: { icon: typeof Activity; label: string; value: string; color?: string }) {
  return (
    <div className="rounded-xl border border-zinc-200 bg-white p-4 shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
      <div className="flex items-center gap-2 text-xs text-zinc-500"><Icon size={14} />{label}</div>
      <div className="mt-1 text-2xl font-bold" style={color ? { color } : undefined}>{value}</div>
    </div>
  );
}
