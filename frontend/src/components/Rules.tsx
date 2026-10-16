import { BookOpen, Search } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import type { Rule } from '../types';
import { Card, Pill, SevBadge, Spinner, cls, inputCls } from './ui';

export function Rules() {
  const [rules, setRules] = useState<Rule[] | null>(null);
  const [q, setQ] = useState('');
  const [dim, setDim] = useState('all');
  const [sel, setSel] = useState<string | null>(null);
  useEffect(() => { api.rules().then(setRules).catch(() => setRules([])); }, []);
  const list = useMemo(() => (rules ?? []).filter((r) => (dim === 'all' || r.dimension === dim) &&
    (!q || `${r.id} ${r.title} ${r.description} ${[...r.standards.owasp_mcp, ...r.standards.cwe].join(' ')}`.toLowerCase().includes(q.toLowerCase()))), [rules, q, dim]);
  if (!rules) return <Spinner label="Loading rules…" />;
  return (
    <div className="space-y-4">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-bold"><BookOpen size={22} />Rule catalogue</h1>
        <p className="text-sm text-zinc-500">{rules.length} rules mapped to OWASP MCP Top 10, OWASP LLM Top 10, CWE and the MCP specification. Add organisation rules as YAML in the custom rules folder.</p>
      </div>
      <div className="flex flex-wrap gap-2">
        <div className="relative"><Search size={14} className="absolute left-2.5 top-2.5 text-zinc-400" /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search…" className={cls(inputCls, 'w-64 pl-8')} /></div>
        <select className={cls(inputCls, 'w-48')} value={dim} onChange={(e) => setDim(e.target.value)}>
          <option value="all">All dimensions</option>
          {['security', 'scalability', 'performance', 'reliability', 'observability', 'maintainability'].map((d) => <option key={d} value={d}>{d}</option>)}
        </select>
      </div>
      <Card>
        <div className="-m-4 divide-y divide-zinc-100 dark:divide-zinc-800">
          {list.map((r) => (
            <div key={r.id}>
              <button onClick={() => setSel(sel === r.id ? null : r.id)} className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-zinc-50 dark:hover:bg-zinc-800/40">
                <code className="w-16 shrink-0 text-xs text-zinc-500">{r.id}</code><SevBadge sev={r.severity} />
                <span className="flex-1 text-sm font-medium">{r.title}</span>
                <span className="hidden text-xs text-zinc-500 sm:block">{r.dimension}</span>
              </button>
              {sel === r.id && (
                <div className="space-y-2 bg-zinc-50 px-4 py-3 text-sm dark:bg-zinc-900/60">
                  <p>{r.description}</p>
                  {r.impact && <p><b>Impact.</b> {r.impact}</p>}
                  <p><b>Remediation.</b> {r.remediation}</p>
                  <div className="flex flex-wrap gap-1.5">{[...r.standards.owasp_mcp, ...r.standards.owasp_llm, ...r.standards.cwe, ...r.standards.mcp_spec].map((s) => <Pill key={s}>{s}</Pill>)}<Pill>effort {r.effort}</Pill></div>
                </div>
              )}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
