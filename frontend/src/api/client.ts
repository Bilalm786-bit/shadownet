import axios from 'axios';

const API_BASE = '/api/v1';
const api = axios.create({ baseURL: API_BASE });

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('shadownet_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('shadownet_token');
      localStorage.removeItem('shadownet_user');
      if (window.location.pathname !== '/login') window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

// Auth
export const authAPI = {
  login: (username: string, password: string) => api.post('/auth/login', { username, password }),
  register: (data: { email: string; username: string; password: string; full_name?: string }) => api.post('/auth/register', data),
  me: () => api.get('/auth/me'),
};

// Cases
export const casesAPI = {
  list: (status?: string) => api.get('/cases/', { params: status ? { status } : {} }),
  get: (id: string) => api.get(`/cases/${id}`),
  create: (data: { name: string; description?: string; priority?: number; tags?: string[] }) => api.post('/cases/', data),
  update: (id: string, data: any) => api.patch(`/cases/${id}`, data),
  delete: (id: string) => api.delete(`/cases/${id}`),
};

// Targets
export const targetsAPI = {
  list: (caseId: string) => api.get(`/cases/${caseId}/targets/`),
  create: (caseId: string, data: { target_type: string; value: string; label?: string }) => api.post(`/cases/${caseId}/targets/`, data),
  delete: (caseId: string, targetId: string) => api.delete(`/cases/${caseId}/targets/${targetId}`),
};

// OSINT Scanning
export const osintAPI = {
  scan: (data: { target_id: string; modules?: string[]; options?: any }) => api.post('/osint/scan', data),
  results: (targetId: string) => api.get(`/osint/results/${targetId}`),
  status: (scanId: string) => api.get(`/osint/status/${scanId}`),
  modules: () => api.get('/osint/modules'),
  autoInvestigate: (data: { target: string; target_type?: string; depth?: number }) => api.post('/osint/auto-investigate', data),
  quickScan: (data: { target: string; module: string; options?: any }) => api.post('/osint/quick-scan', data),
  detectType: (target: string) => api.get('/osint/detect-type', { params: { target } }),
};

// Investigation — 3 pillars
export const investigateAPI = {
  person: (data: {
    target: string;
    username?: string;
    email?: string;
    phone?: string;
    cnic?: string;
    name?: string;
    photo_url?: string;
    aliases?: string[];
  }) => api.post('/investigate/person', data),
  network: (target: string) => api.post('/investigate/network', { target }),
  website: (target: string) => api.post('/investigate/website', { target }),
  exploit: (target: string) => api.post('/investigate/exploit', { target }),
};

// Dashboard
export const dashboardAPI = {
  stats: () => api.get('/dashboard/stats'),
};

// Alerts
export const alertsAPI = {
  list: (params?: { severity?: string; is_read?: boolean }) => api.get('/alerts/', { params }),
  unreadCount: () => api.get('/alerts/unread-count'),
  markRead: (id: string) => api.patch(`/alerts/${id}/read`),
  markAllRead: () => api.patch('/alerts/read-all'),
};

// Search
export const searchAPI = {
  search: (q: string) => api.get('/search/', { params: { q } }),
  searchCase: (caseId: string, q?: string) => api.get(`/search/case/${caseId}`, { params: q ? { q } : {} }),
};

// Graph
export const graphAPI = {
  caseGraph: (caseId: string) => api.get(`/graph/case/${caseId}`),
  entityGraph: (entityId: string, depth?: number) => api.get(`/graph/entity/${entityId}`, { params: { depth } }),
};

// Reports
export const reportsAPI = {
  generate: (caseId: string) => api.post(`/reports/generate/${caseId}`),
};

// Dark Web
export const darkwebAPI = {
  search: (q: string, limit?: number) => api.get('/darkweb/search', { params: { q, limit } }),
  scan: (q: string) => api.get('/darkweb/scan', { params: { q } }),
  breaches: (q: string) => api.get('/darkweb/breaches', { params: { q } }),
  dorks: (q: string) => api.get('/darkweb/dorks', { params: { q } }),
  status: () => api.get('/darkweb/status'),
  exportResults: (q: string, format: string = 'json') => api.get('/darkweb/export', { params: { q, format } }),
};

// Threat Intelligence
export const threatIntelAPI = {
  status: () => api.get('/threat-intel/status'),
  feeds: () => api.get('/threat-intel/feeds'),
  refresh: (feeds?: string[]) => api.post('/threat-intel/refresh', feeds || null),
  indicators: (params?: { type?: string; severity?: string; source?: string; limit?: number }) =>
    api.get('/threat-intel/indicators', { params }),
  lookup: (value: string) => api.get('/threat-intel/lookup', { params: { value } }),
  summary: () => api.get('/threat-intel/summary'),
};

// Cursor Cloud Agent
export const cursorAgentAPI = {
  create: (data: { prompt: string; repo_url: string; starting_ref?: string; model_id?: string; auto_create_pr?: boolean; branch_name?: string }) => api.post('/cursor-agent/create', data),
  agents: (limit?: number) => api.get('/cursor-agent/agents', { params: { limit } }),
  getAgent: (id: string) => api.get(`/cursor-agent/agents/${id}`),
  archiveAgent: (id: string) => api.post(`/cursor-agent/agents/${id}/archive`),
  deleteAgent: (id: string) => api.delete(`/cursor-agent/agents/${id}`),
  createRun: (agentId: string, prompt: string) => api.post(`/cursor-agent/agents/${agentId}/run`, { prompt }),
  listRuns: (agentId: string) => api.get(`/cursor-agent/agents/${agentId}/runs`),
  getRun: (agentId: string, runId: string) => api.get(`/cursor-agent/agents/${agentId}/runs/${runId}`),
  cancelRun: (agentId: string, runId: string) => api.post(`/cursor-agent/agents/${agentId}/cancel/${runId}`),
  listArtifacts: (agentId: string) => api.get(`/cursor-agent/artifacts/${agentId}`),
  downloadArtifact: (agentId: string, path: string) => api.get(`/cursor-agent/artifacts/${agentId}/download`, { params: { path } }),
  models: () => api.get('/cursor-agent/models'),
  me: () => api.get('/cursor-agent/me'),
};

export default api;
