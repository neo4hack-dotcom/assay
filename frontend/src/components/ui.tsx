import { AlertTriangle, CheckCircle2, Loader2, X, type LucideIcon } from 'lucide-react';
import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react';
import type { Decision, Severity } from '../types';

export function cls(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ');
}

// ---------------------------------------------------------------- colors
export const SEV_STYLE: Record<Severity, string> = {
  critical: 'bg-red-700 text-white',
  high: 'bg-orange-600 text-white',
  medium: 'bg-amber-500 text-white',
  low: 'bg-blue-600 text-white',
  info: 'bg-zinc-500 text-white',
};
export const SEV_HEX: Record<Severity, string> = { critical: '#b91c1c', high: '#ea580c', medium: '#d97706', low: '#2563eb', info: '#71717a' };
export const DECISION_STYLE: Record<Decision, string> = {
  GO: 'bg-green-700 text-white',
  GO_WITH_CONDITIONS: 'bg-yellow-600 text-white',
  NOT_READY: 'bg-orange-600 text-white',
  NO_GO: 'bg-red-700 text-white',
};
export function scoreHex(s: number): string {
  return s >= 80 ? '#15803d' : s >= 65 ? '#65a30d' : s >= 45 ? '#d97706' : '#b91c1c';
}

// ---------------------------------------------------------------- primitives
interface ButtonProps extends React.ComponentProps<'button'> {
  variant?: 'primary' | 'outline' | 'ghost' | 'danger';
  size?: 'sm' | 'md';
  icon?: LucideIcon;
  busy?: boolean;
}
const BTN: Record<string, string> = {
  primary: 'bg-brand-600 text-white hover:bg-brand-700 disabled:bg-brand-400 shadow-sm',
  outline: 'border border-zinc-300 dark:border-zinc-700 text-zinc-700 dark:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800',
  ghost: 'text-zinc-600 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800',
  danger: 'bg-red-600 text-white hover:bg-red-700 disabled:bg-red-400 shadow-sm',
};
export function Button({ variant = 'primary', size = 'md', icon: Icon, busy, className, children, disabled, ...rest }: ButtonProps) {
  return (
    <button
      className={cls('inline-flex items-center justify-center gap-1.5 rounded-lg font-medium transition-colors',
        'disabled:cursor-not-allowed disabled:opacity-60 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500',
        size === 'sm' ? 'px-2.5 py-1.5 text-xs' : 'px-3.5 py-2 text-sm', BTN[variant], className)}
      disabled={disabled || busy} {...rest}>
      {busy ? <Loader2 size={size === 'sm' ? 13 : 15} className="animate-spin" /> : Icon && <Icon size={size === 'sm' ? 13 : 15} />}
      {children}
    </button>
  );
}

export function Card({ title, actions, children, className }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cls('rounded-xl border border-zinc-200 bg-white shadow-sm dark:border-zinc-800 dark:bg-zinc-900', className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-2 border-b border-zinc-200 px-4 py-3 dark:border-zinc-800">
          <h3 className="text-sm font-semibold text-zinc-800 dark:text-zinc-100">{title}</h3>
          <div className="flex items-center gap-2">{actions}</div>
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function SevBadge({ sev, className }: { sev: Severity; className?: string }) {
  return <span className={cls('inline-flex rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide', SEV_STYLE[sev], className)}>{sev}</span>;
}

export function Pill({ children, tone = 'zinc' }: { children: ReactNode; tone?: 'zinc' | 'green' | 'red' | 'brand' | 'amber' }) {
  const t = {
    zinc: 'bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300',
    green: 'bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-300',
    red: 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300',
    brand: 'bg-brand-100 text-brand-800 dark:bg-brand-950 dark:text-brand-300',
    amber: 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300',
  }[tone];
  return <span className={cls('inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium', t)}>{children}</span>;
}

export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-zinc-600 dark:text-zinc-400">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-zinc-500">{hint}</span>}
    </label>
  );
}

export const inputCls = 'w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-500/20 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100';

export function Segmented<T extends string>({ value, options, onChange }: { value: T; options: { value: T; label: string; icon?: LucideIcon }[]; onChange: (v: T) => void }) {
  return (
    <div className="inline-flex flex-wrap rounded-lg border border-zinc-300 bg-zinc-100 p-0.5 dark:border-zinc-700 dark:bg-zinc-800">
      {options.map(({ value: v, label, icon: Icon }) => (
        <button key={v} type="button" onClick={() => onChange(v)}
          className={cls('inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors',
            v === value ? 'bg-white text-brand-700 shadow-sm dark:bg-zinc-950 dark:text-brand-300' : 'text-zinc-600 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-100')}>
          {Icon && <Icon size={14} />}{label}
        </button>
      ))}
    </div>
  );
}

export function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button type="button" onClick={() => onChange(!checked)} className="inline-flex items-center gap-2 text-sm">
      <span className={cls('relative inline-flex h-5 w-9 items-center rounded-full transition-colors', checked ? 'bg-brand-600' : 'bg-zinc-300 dark:bg-zinc-700')}>
        <span className={cls('inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform', checked ? 'translate-x-4' : 'translate-x-0.5')} />
      </span>
      {label}
    </button>
  );
}

export function Empty({ icon: Icon, title, children }: { icon: LucideIcon; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-zinc-300 px-6 py-14 text-center dark:border-zinc-700">
      <Icon size={30} className="text-zinc-400" />
      <div className="font-medium">{title}</div>
      {children && <div className="max-w-md text-sm text-zinc-500">{children}</div>}
    </div>
  );
}

export function Spinner({ label }: { label?: string }) {
  return <div className="flex items-center gap-2 text-sm text-zinc-500"><Loader2 size={16} className="animate-spin" />{label}</div>;
}

// ---------------------------------------------------------------- charts (hand-rolled SVG)
export function Gauge({ value, label, color, size = 168 }: { value: number; label: string; color?: string; size?: number }) {
  const r = 64, cx = 80, cy = 78;
  const v = Math.max(0, Math.min(100, value));
  const ang = Math.PI * (1 - v / 100);
  const x = cx + r * Math.cos(ang), y = cy - r * Math.sin(ang);
  return (
    <svg viewBox="0 0 160 100" width={size} role="img" aria-label={`${label} ${value}%`}>
      <path d="M16 78 A64 64 0 0 1 144 78" fill="none" className="stroke-zinc-200 dark:stroke-zinc-800" strokeWidth="14" strokeLinecap="round" />
      {v > 0 && <path d={`M16 78 A64 64 0 0 1 ${x.toFixed(1)} ${y.toFixed(1)}`} fill="none" stroke={color ?? scoreHex(v)} strokeWidth="14" strokeLinecap="round" />}
      <text x="80" y="72" textAnchor="middle" className="fill-zinc-900 dark:fill-zinc-50" fontSize="26" fontWeight="800">{value}%</text>
      <text x="80" y="95" textAnchor="middle" className="fill-zinc-500" fontSize="10.5">{label}</text>
    </svg>
  );
}

export function ScoreBar({ score, className }: { score: number; className?: string }) {
  return (
    <div className={cls('h-2 w-full overflow-hidden rounded-full bg-zinc-200 dark:bg-zinc-800', className)}>
      <div className="h-full rounded-full" style={{ width: `${Math.max(2, score)}%`, background: scoreHex(score) }} />
    </div>
  );
}

export function Radar({ items, size = 260 }: { items: { label: string; value: number }[]; size?: number }) {
  const n = items.length, c = 130, R = 92;
  const pt = (i: number, v: number) => {
    const a = -Math.PI / 2 + (2 * Math.PI * i) / n;
    return [c + R * (v / 100) * Math.cos(a), c + R * (v / 100) * Math.sin(a)];
  };
  const poly = items.map((it, i) => pt(i, it.value).map((x) => x.toFixed(1)).join(',')).join(' ');
  return (
    <svg viewBox="0 0 260 260" width={size} role="img" aria-label="Scores radar">
      {[25, 50, 75, 100].map((g) => (
        <polygon key={g} points={items.map((_, i) => pt(i, g).join(',')).join(' ')} fill="none" className="stroke-zinc-200 dark:stroke-zinc-800" />
      ))}
      {items.map((_, i) => { const [x, y] = pt(i, 100); return <line key={i} x1={c} y1={c} x2={x} y2={y} className="stroke-zinc-200 dark:stroke-zinc-800" />; })}
      <polygon points={poly} fill="rgba(79,70,229,.18)" stroke="#4f46e5" strokeWidth="2" />
      {items.map((it, i) => {
        const [x, y] = pt(i, 120);
        const short = it.label.split(/[ &]/)[0];
        return <text key={i} x={x} y={y} textAnchor="middle" dominantBaseline="middle" fontSize="10.5" className="fill-zinc-600 dark:fill-zinc-400">{short} {it.value}</text>;
      })}
    </svg>
  );
}

// ---------------------------------------------------------------- toasts & confirm
type ToastKind = 'success' | 'error';
const ToastCtx = createContext<(msg: string, kind?: ToastKind) => void>(() => {});
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<{ id: number; msg: string; kind: ToastKind }[]>([]);
  const seq = useRef(0);
  const push = useCallback((msg: string, kind: ToastKind = 'success') => {
    const id = ++seq.current;
    setToasts((t) => [...t, { id, msg, kind }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), kind === 'error' ? 7000 : 3500);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="fixed bottom-4 right-4 z-50 flex max-w-sm flex-col gap-2">
        {toasts.map((t) => (
          <div key={t.id} className={cls('flex items-start gap-2 rounded-lg px-4 py-2.5 text-sm text-white shadow-lg',
            t.kind === 'error' ? 'bg-red-600' : 'bg-zinc-900 dark:bg-zinc-100 dark:text-zinc-900')}>
            {t.kind === 'error' ? <AlertTriangle size={16} className="mt-0.5 shrink-0" /> : <CheckCircle2 size={16} className="mt-0.5 shrink-0" />}
            <span className="break-words">{t.msg}</span>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

const ConfirmCtx = createContext<(msg: string, danger?: boolean) => Promise<boolean>>(async () => false);
export const useConfirm = () => useContext(ConfirmCtx);

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<{ msg: string; danger: boolean; resolve: (v: boolean) => void } | null>(null);
  const ask = useCallback((msg: string, danger = false) => new Promise<boolean>((resolve) => setState({ msg, danger, resolve })), []);
  const close = (v: boolean) => { state?.resolve(v); setState(null); };
  return (
    <ConfirmCtx.Provider value={ask}>
      {children}
      {state && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" onClick={() => close(false)}>
          <div className="w-full max-w-md rounded-xl bg-white p-5 shadow-xl dark:bg-zinc-900" onClick={(e) => e.stopPropagation()}>
            <div className="mb-4 text-sm">{state.msg}</div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => close(false)}>Cancel</Button>
              <Button variant={state.danger ? 'danger' : 'primary'} onClick={() => close(true)}>Confirm</Button>
            </div>
          </div>
        </div>
      )}
    </ConfirmCtx.Provider>
  );
}

export function Modal({ title, onClose, children, wide }: { title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40 p-4" onClick={onClose}>
      <div className={cls('max-h-[90vh] w-full overflow-auto rounded-xl bg-white shadow-xl dark:bg-zinc-900', wide ? 'max-w-3xl' : 'max-w-lg')} onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-zinc-200 px-5 py-3 dark:border-zinc-800">
          <h3 className="font-semibold">{title}</h3>
          <button onClick={onClose} className="rounded p-1 hover:bg-zinc-100 dark:hover:bg-zinc-800" aria-label="Close"><X size={16} /></button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}

export function fmtDate(ts: number | null | undefined): string {
  return ts ? new Date(ts * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—';
}
