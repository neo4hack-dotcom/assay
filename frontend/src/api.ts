import type {
  AuditResult, AuditSummary, BrowseResult, Health, LlmSettings, LlmTestReport, Rule, ScannerInfo, ScannerSettings, SettingsResponse, StageLog,
} from './types';

const TOKEN_KEY = 'assay-token';

export function getToken(): string {
  try { return localStorage.getItem(TOKEN_KEY) ?? ''; } catch { return ''; }
}
export function setToken(t: string) {
  try { if (t) localStorage.setItem(TOKEN_KEY, t); else localStorage.removeItem(TOKEN_KEY); } catch { /* storage unavailable */ }
}

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

async function raw(path: string, init?: RequestInit): Promise<Response> {
  const token = getToken();
  const res = await fetch(`/api${path}`, {
    ...init,
    headers: {
      ...(init?.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    let msg = await res.text();
    try { const j = JSON.parse(msg); msg = typeof j.detail === 'string' ? j.detail : JSON.stringify(j.detail); } catch { /* not JSON */ }
    throw new ApiError(res.status, msg.slice(0, 400) || `HTTP ${res.status}`);
  }
  return res;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  return (await raw(path, init)).json() as Promise<T>;
}

export const api = {
  // Meta
  health: () => request<Health>('/health'),
  rules: () => request<Rule[]>('/rules'),
  scanners: () => request<ScannerInfo[]>('/scanners'),
  browse: (path = '') => request<BrowseResult>(`/browse?path=${encodeURIComponent(path)}`),

  // Settings
  settings: () => request<SettingsResponse>('/settings'),
  saveLlm: (s: LlmSettings) => request<LlmSettings>('/settings/llm', { method: 'PUT', body: JSON.stringify(s) }),
  saveScanners: (s: ScannerSettings) => request<ScannerSettings>('/settings/scanners', { method: 'PUT', body: JSON.stringify(s) }),
  testLlm: (s?: LlmSettings) => request<LlmTestReport>('/llm/test', { method: 'POST', body: s ? JSON.stringify(s) : undefined }),
  listModels: (s?: LlmSettings) => request<{ models: string[] }>('/llm/models', { method: 'POST', body: s ? JSON.stringify(s) : undefined }),

  // Audits
  audits: () => request<AuditSummary[]>('/audits'),
  portfolio: () => request<AuditSummary[]>('/portfolio'),
  audit: (id: string) => request<AuditResult>(`/audits/${id}`),
  status: (id: string) => request<AuditSummary & { logs: StageLog[] }>(`/audits/${id}/status`),
  createAudit: (form: FormData) => request<AuditSummary>('/audits', { method: 'POST', body: form }),
  deleteAudit: (id: string) => request<{ ok: boolean }>(`/audits/${id}`, { method: 'DELETE' }),
  cancelAudit: (id: string) => request<{ ok: boolean }>(`/audits/${id}/cancel`, { method: 'POST' }),
  rerun: (id: string) => request<AuditSummary>(`/audits/${id}/rerun`, { method: 'POST' }),
  triage: (id: string, fingerprint: string, body: { status: string; reason: string; by: string; remember: boolean }) =>
    request<AuditSummary>(`/audits/${id}/findings/${fingerprint}`, { method: 'PATCH', body: JSON.stringify(body) }),

  // Reports: fetched as a blob so the auth header is sent, then saved by the browser
  download: async (id: string, fmt: string) => {
    const res = await raw(`/audits/${id}/report/${fmt}`);
    const cd = res.headers.get('Content-Disposition') ?? '';
    const name = /filename="([^"]+)"/.exec(cd)?.[1] ?? `assay-report.${fmt}`;
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement('a');
    a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  },
  openHtml: async (id: string) => {
    const res = await raw(`/audits/${id}/report/html`);
    const url = URL.createObjectURL(new Blob([await res.text()], { type: 'text/html' }));
    window.open(url, '_blank', 'noopener');
  },
};
