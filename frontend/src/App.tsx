import { BookOpen, FlaskConical, KeyRound, LayoutDashboard, Moon, Plus, Settings as SettingsIcon, Sparkles, Sun, type LucideIcon } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { ApiError, api, getToken, setToken } from './api';
import { AuditDetail } from './components/AuditDetail';
import { Dashboard } from './components/Dashboard';
import { NewAudit } from './components/NewAudit';
import { Rules } from './components/Rules';
import { Settings } from './components/Settings';
import { Button, Field, Modal, cls, inputCls } from './components/ui';
import type { Health } from './types';

type View = { tab: 'dashboard' } | { tab: 'new' } | { tab: 'audit'; id: string } | { tab: 'rules' } | { tab: 'settings' };
const NAV: { tab: 'dashboard' | 'new' | 'rules' | 'settings'; label: string; icon: LucideIcon }[] = [
  { tab: 'dashboard', label: 'Portfolio', icon: LayoutDashboard }, { tab: 'new', label: 'New audit', icon: Plus },
  { tab: 'rules', label: 'Rules', icon: BookOpen }, { tab: 'settings', label: 'Settings', icon: SettingsIcon },
];

function readHash(): View {
  const h = location.hash.replace(/^#\/?/, '');
  const [tab, id] = h.split('/');
  if (tab === 'audit' && id) return { tab: 'audit', id };
  if (tab === 'new' || tab === 'rules' || tab === 'settings') return { tab };
  return { tab: 'dashboard' };
}

export default function App() {
  const [view, setView] = useState<View>(readHash);
  const [health, setHealth] = useState<Health | null>(null);
  const [needToken, setNeedToken] = useState(false);
  const [dark, setDark] = useState(() => document.documentElement.classList.contains('dark'));

  // the hash keeps a shareable link to an audit and makes the browser back button work
  const go = useCallback((v: View) => {
    location.hash = v.tab === 'audit' ? `/audit/${v.id}` : `/${v.tab}`;
  }, []);
  useEffect(() => {
    const on = () => setView(readHash());
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);

  const loadHealth = useCallback(() => {
    api.health().then((h) => {
      setHealth(h);
      if (h.auth_required && !getToken()) setNeedToken(true);
    }).catch(() => setHealth(null));
  }, []);
  useEffect(() => { loadHealth(); }, [loadHealth]);
  useEffect(() => {
    const onErr = (e: PromiseRejectionEvent) => { if (e.reason instanceof ApiError && e.reason.status === 401) setNeedToken(true); };
    window.addEventListener('unhandledrejection', onErr);
    return () => window.removeEventListener('unhandledrejection', onErr);
  }, []);

  const toggleDark = () => {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle('dark', next);
    try { localStorage.setItem('assay-theme', next ? 'dark' : 'light'); } catch { /* ignore */ }
  };
  const active = view.tab === 'audit' ? 'dashboard' : view.tab;

  return (
    <div className="flex min-h-screen flex-col md:flex-row">
      <aside className="flex shrink-0 flex-row items-center gap-1 border-b border-zinc-200 bg-white px-3 py-2 dark:border-zinc-800 dark:bg-zinc-900 md:w-60 md:flex-col md:items-stretch md:border-b-0 md:border-r md:px-3 md:py-5">
        <div className="mr-3 flex items-center gap-2 px-2 md:mb-6 md:mr-0">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-700 text-white"><FlaskConical size={17} /></div>
          <div className="hidden sm:block"><div className="font-bold leading-tight">Assay</div><div className="text-[11px] text-zinc-500">MCP readiness auditor</div></div>
        </div>
        <nav className="flex flex-1 gap-1 overflow-x-auto md:flex-col">
          {NAV.map(({ tab, label, icon: Icon }) => (
            <button key={tab} onClick={() => go({ tab } as View)}
              className={cls('flex shrink-0 items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium',
                active === tab ? 'bg-brand-50 text-brand-700 dark:bg-brand-950 dark:text-brand-300' : 'text-zinc-600 hover:bg-zinc-100 dark:text-zinc-300 dark:hover:bg-zinc-800')}>
              <Icon size={16} /><span className="hidden sm:inline">{label}</span>
            </button>
          ))}
        </nav>
        <div className="flex items-center gap-1 md:flex-col md:items-stretch md:gap-2">
          <button onClick={() => go({ tab: 'settings' })} title="LLM status"
            className={cls('hidden items-center gap-2 rounded-lg px-3 py-2 text-left text-xs md:flex', health?.llm_configured ? 'bg-green-50 text-green-800 dark:bg-green-950/50 dark:text-green-300' : 'bg-amber-50 text-amber-800 dark:bg-amber-950/50 dark:text-amber-300')}>
            <Sparkles size={14} className="shrink-0" />
            <span className="truncate">{health === null ? 'API unreachable' : health.llm_configured ? health.llm_model : 'No LLM configured'}</span>
          </button>
          <div className="flex items-center gap-1 md:justify-between md:px-1">
            <button onClick={toggleDark} className="rounded-lg p-2 text-zinc-500 hover:bg-zinc-100 dark:hover:bg-zinc-800" aria-label="Toggle dark mode">{dark ? <Sun size={16} /> : <Moon size={16} />}</button>
            {health?.auth_required && <button onClick={() => setNeedToken(true)} className="rounded-lg p-2 text-zinc-500 hover:bg-zinc-100 dark:hover:bg-zinc-800" aria-label="Access token"><KeyRound size={16} /></button>}
            <span className="hidden text-[11px] text-zinc-400 md:inline">v{health?.version ?? '—'}</span>
          </div>
        </div>
      </aside>
      <main className="min-w-0 flex-1 px-4 py-6 md:px-8">
        {health === null && <div className="mb-4 rounded-lg bg-red-50 p-3 text-sm text-red-800 dark:bg-red-950 dark:text-red-200">The Assay API is not reachable. Start it with <code>run.bat</code> / <code>./run.sh</code>.</div>}
        {view.tab === 'dashboard' && <Dashboard onOpen={(id) => go({ tab: 'audit', id })} onNew={() => go({ tab: 'new' })} />}
        {view.tab === 'new' && <NewAudit health={health} onCreated={(id) => go({ tab: 'audit', id })} onSettings={() => go({ tab: 'settings' })} />}
        {view.tab === 'audit' && <AuditDetail id={view.id} onBack={() => go({ tab: 'dashboard' })} onOpen={(id) => go({ tab: 'audit', id })} />}
        {view.tab === 'rules' && <Rules />}
        {view.tab === 'settings' && <Settings onSaved={loadHealth} />}
      </main>
      {needToken && <TokenModal onClose={() => { setNeedToken(false); loadHealth(); }} />}
    </div>
  );
}

function TokenModal({ onClose }: { onClose: () => void }) {
  const [t, setT] = useState(getToken());
  return (
    <Modal title="Access token required" onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-zinc-500">This Assay server is protected. Enter the token configured in ASSAY_AUTH_TOKEN.</p>
        <Field label="Token"><input type="password" className={inputCls} value={t} onChange={(e) => setT(e.target.value)} autoFocus /></Field>
        <div className="flex justify-end"><Button onClick={() => { setToken(t.trim()); onClose(); location.reload(); }}>Save</Button></div>
      </div>
    </Modal>
  );
}
