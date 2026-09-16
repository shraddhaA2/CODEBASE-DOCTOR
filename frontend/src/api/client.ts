import {
  Scan,
  Finding,
  ArchitectureSummary,
  HealthScore,
  AiReport,
  PatchProposal,
  AiData,
} from './types';

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

class ApiError extends Error {
  status: number;
  detail: string;

  constructor(status: number, detail: string) {
    super(detail);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE}${path}`;
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  const res = await fetch(url, { ...options, headers });
  
  if (!res.ok) {
    let errorDetail = `HTTP ${res.status} ${res.statusText}`;
    try {
      const errorJson = await res.json();
      if (errorJson.detail) {
        errorDetail = typeof errorJson.detail === 'string' 
          ? errorJson.detail 
          : JSON.stringify(errorJson.detail);
      }
    } catch {
      // Non-JSON response
    }
    throw new ApiError(res.status, errorDetail);
  }

  return res.json() as Promise<T>;
}

export const api = {
  /** Submit a new repository URL for scanning */
  async createScan(githubUrl: string, limits?: Record<string, any>): Promise<{ scan_id: string }> {
    return request<{ scan_id: string }>('/api/scans', {
      method: 'POST',
      body: JSON.stringify({ github_url: githubUrl, limits }),
    });
  },

  /** Get list of recent scans */
  async listScans(limit: number = 20): Promise<Scan[]> {
    return request<Scan[]>(`/api/scans?limit=${limit}`);
  },

  /** Get scan status and summary */
  async getScan(scanId: string): Promise<Scan> {
    return request<Scan>(`/api/scans/${scanId}`);
  },

  /** Get filtered findings for a scan */
  async getFindings(
    scanId: string,
    filters?: { category?: string; severity?: string; analyzer?: string; scope?: string; include_duplicates?: boolean }
  ): Promise<Finding[]> {
    const params = new URLSearchParams();
    if (filters?.category) params.append('category', filters.category);
    if (filters?.severity) params.append('severity', filters.severity);
    if (filters?.analyzer) params.append('analyzer', filters.analyzer);
    if (filters?.scope) params.append('scope', filters.scope);
    if (filters?.include_duplicates !== undefined) params.append('include_duplicates', String(filters.include_duplicates));
    const qs = params.toString();
    return request<Finding[]>(`/api/scans/${scanId}/findings${qs ? `?${qs}` : ''}`);
  },

  /** Get architecture metrics and coupling graph summary */
  async getArchitecture(scanId: string): Promise<ArchitectureSummary> {
    return request<ArchitectureSummary>(`/api/scans/${scanId}/architecture`);
  },

  /** Get deterministic health score and auditable breakdown */
  async getScore(scanId: string): Promise<HealthScore> {
    return request<HealthScore>(`/api/scans/${scanId}/score`);
  },

  /** Trigger AI diagnosis */
  async generateDiagnosis(scanId: string): Promise<AiReport> {
    return request<AiReport>(`/api/scans/${scanId}/ai/diagnose`, {
      method: 'POST',
      body: JSON.stringify({}),
    });
  },

  /** Trigger AI patch proposals */
  async generateFixes(scanId: string, findingIds?: string[]): Promise<PatchProposal[]> {
    return request<PatchProposal[]>(`/api/scans/${scanId}/ai/fixes`, {
      method: 'POST',
      body: JSON.stringify({ finding_ids: findingIds }),
    });
  },

  /** Get saved AI reports and patch proposals */
  async getAIReports(scanId: string): Promise<AiData> {
    return request<AiData>(`/api/scans/${scanId}/ai`);
  },

  /** Health check */
  async checkHealth(): Promise<{ status: string }> {
    return request<{ status: string }>('/health');
  },
};
