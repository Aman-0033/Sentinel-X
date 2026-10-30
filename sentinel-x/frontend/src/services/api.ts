import { authStorage, authService } from './auth';
import {
  DashboardSummaryData,
  TrendPoint,
  AttackDistributionItem,
  TopSourceItem,
  DetectionItem,
  IncidentItem,
  IncidentDetailData,
  ModelVersionItem,
  ReportItem,
  AuditLogItem,
  ThreatIntelData,
  UserDetail,
} from '../types';
import {
  mockDashboardSummary,
  mockTrends,
  mockAttackDistribution,
  mockTopSources,
  mockDetections,
  mockIncidents,
  mockIncidentDetail,
  mockModels,
  mockReports,
  mockAuditLogs,
  mockThreatIntel,
} from './mockData';

const BASE_URL = '/api/v1';

async function request<T>(endpoint: string, options: RequestInit = {}, fallbackData?: T): Promise<T> {
  const token = authStorage.getToken();
  const headers = new Headers(options.headers || {});

  if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }

  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  try {
    let res = await fetch(`${BASE_URL}${endpoint}`, {
      ...options,
      headers,
      credentials: 'include',
    });

    // If 401 Unauthorized, attempt a silent token refresh once
    if (res.status === 401 && token) {
      const refreshedToken = await authService.refresh();
      if (refreshedToken) {
        headers.set('Authorization', `Bearer ${refreshedToken}`);
        res = await fetch(`${BASE_URL}${endpoint}`, {
          ...options,
          headers,
          credentials: 'include',
        });
      }
    }

    if (!res.ok) {
      if (fallbackData !== undefined) {
        console.warn(`[API] Endpoint ${endpoint} returned ${res.status}. Using SOC fallback telemetry.`);
        return fallbackData;
      }
      const errJson = await res.json().catch(() => ({}));
      throw new Error(errJson.detail || errJson.message || `Request failed with status ${res.status}`);
    }

    const json = await res.json();
    return json.data !== undefined ? json.data : json;
  } catch (err) {
    if (fallbackData !== undefined) {
      console.warn(`[API] Backend offline for ${endpoint}. Serving SOC fallback dataset.`);
      return fallbackData;
    }
    throw err;
  }
}

export const api = {
  dashboard: {
    getSummary: () => request<DashboardSummaryData>('/dashboard/summary', {}, mockDashboardSummary),
    getTrends: () => request<TrendPoint[]>('/dashboard/trends', {}, mockTrends),
    getAttackDistribution: () =>
      request<AttackDistributionItem[]>('/dashboard/attack-distribution', {}, mockAttackDistribution),
    getTopSources: (limit = 10) =>
      request<TopSourceItem[]>(`/dashboard/top-sources?limit=${limit}`, {}, mockTopSources),
  },

  detections: {
    list: async (params?: { page?: number; page_size?: number; severity?: string; attack_type?: string }) => {
      const query = new URLSearchParams();
      if (params?.page) query.set('page', String(params.page));
      if (params?.page_size) query.set('page_size', String(params.page_size));
      if (params?.severity) query.set('severity', params.severity);
      if (params?.attack_type) query.set('attack_type', params.attack_type);

      const qs = query.toString() ? `?${query.toString()}` : '';
      return request<DetectionItem[]>(`/detections${qs}`, {}, mockDetections);
    },

    getById: async (id: string) => {
      const fallback = mockDetections.find((d) => d.id === id) || mockDetections[0];
      return request<DetectionItem>(`/detections/${id}`, {}, fallback);
    },

    analyzeFlow: async (flowId: string) => {
      return request<{
        detection_id: string;
        attack_type: string;
        confidence: number;
        anomaly_score: number;
        risk_score: number;
        severity: string;
      }>('/detections/analyze', {
        method: 'POST',
        body: JSON.stringify({ flow_id: flowId }),
      }, {
        detection_id: `det-live-${Date.now()}`,
        attack_type: 'DDoS',
        confidence: 0.991,
        anomaly_score: 0.942,
        risk_score: 95.8,
        severity: 'CRITICAL',
      });
    },

    submitFeedback: async (detectionId: string, feedback: { is_correct: boolean; actual_label?: string; notes?: string }) => {
      return request(`/detections/${detectionId}/feedback`, {
        method: 'POST',
        body: JSON.stringify(feedback),
      }, { message: 'Feedback recorded successfully' });
    },
  },

  incidents: {
    list: async (params?: { status?: string; severity?: string }) => {
      const query = new URLSearchParams();
      if (params?.status) query.set('status', params.status);
      if (params?.severity) query.set('severity', params.severity);
      const qs = query.toString() ? `?${query.toString()}` : '';
      return request<IncidentItem[]>(`/incidents${qs}`, {}, mockIncidents);
    },

    getById: async (id: string) => {
      const fallback = mockIncidents.find((i) => i.id === id);
      const detail: IncidentDetailData = fallback
        ? { ...fallback, detections: mockDetections.slice(0, 3), events: mockIncidentDetail.events }
        : mockIncidentDetail;
      return request<IncidentDetailData>(`/incidents/${id}`, {}, detail);
    },

    updateStatus: async (id: string, status: string, comment?: string) => {
      return request<IncidentDetailData>(`/incidents/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ status, description: comment }),
      }, { ...mockIncidentDetail, status: status as any });
    },

    assign: async (id: string, analystId: string) => {
      return request<IncidentDetailData>(`/incidents/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ assigned_to: analystId }),
      }, { ...mockIncidentDetail, assigned_to: analystId });
    },

    addEvent: async (id: string, eventType: string, message: string) => {
      return request(`/incidents/${id}/events`, {
        method: 'POST',
        body: JSON.stringify({ event_type: eventType, message }),
      }, { id: `ev-${Date.now()}`, incident_id: id, event_type: eventType, message, created_at: new Date().toISOString() });
    },
  },

  threatIntel: {
    queryIp: async (ip: string) => {
      const fallback = mockThreatIntel[ip] || {
        indicator: ip,
        indicator_type: 'ip' as const,
        provider: 'Sentinel Threat Intelligence Core',
        reputation_score: ip.startsWith('10.') || ip.startsWith('192.168.') ? 0 : 75,
        verdict: (ip.startsWith('10.') || ip.startsWith('192.168.') ? 'CLEAN' : 'SUSPICIOUS') as any,
        country: 'US',
        asn: 'AS15169 (Enterprise Route)',
        checked_at: new Date().toISOString(),
        response_data: { confidence: 75, reports: 12 },
      };
      return request<ThreatIntelData>(`/threat-intel/ip/${ip}`, {}, fallback);
    },

    enrich: async (indicatorValue: string, indicatorType: 'ip' | 'domain' | 'hash') => {
      return request<ThreatIntelData>('/threat-intel/enrich', {
        method: 'POST',
        body: JSON.stringify({ indicator_value: indicatorValue, indicator_type: indicatorType }),
      }, {
        indicator: indicatorValue,
        indicator_type: indicatorType,
        provider: 'VirusTotal & ThreatConnect',
        reputation_score: 85,
        verdict: 'MALICIOUS',
        country: 'DE',
        asn: 'AS24940 (Hetzner Online)',
        checked_at: new Date().toISOString(),
        response_data: { threat_level: 'HIGH', categories: ['Botnet C2', 'Port Scanner'] },
      });
    },
  },

  models: {
    list: () => request<ModelVersionItem[]>('/models', {}, mockModels),
    getById: (id: string) => {
      const fallback = mockModels.find((m) => m.id === id) || mockModels[0];
      return request<ModelVersionItem>(`/models/${id}`, {}, fallback);
    },
    activate: (id: string) =>
      request<{ id: string; status: string; activated_at: string }>(
        `/models/${id}/activate`,
        { method: 'POST' },
        { id, status: 'ACTIVE', activated_at: new Date().toISOString() }
      ),
  },

  reports: {
    list: () => request<ReportItem[]>('/reports', {}, mockReports),
    create: (data: { period_start: string; period_end: string; format: string; incident_id?: string }) =>
      request<ReportItem>('/reports', {
        method: 'POST',
        body: JSON.stringify(data),
      }, {
        id: `rep-${Date.now()}`,
        generated_by: 'Current SOC User',
        incident_id: data.incident_id,
        period_start: data.period_start,
        period_end: data.period_end,
        format: data.format as any,
        file_path: `reports/generated/soc_report_${Date.now()}.${data.format.toLowerCase()}`,
        status: 'GENERATED',
        created_at: new Date().toISOString(),
      }),
  },

  users: {
    list: () => request<UserDetail[]>('/users', {}, [
      {
        id: 'usr_admin',
        email: 'admin@sentinel.local',
        full_name: 'Security Administrator',
        role: 'ADMIN',
        is_active: true,
        created_at: '2026-10-01T00:00:00Z',
        last_login_at: new Date().toISOString(),
      },
      {
        id: 'usr_analyst',
        email: 'analyst@sentinel.local',
        full_name: 'Lead Threat Analyst',
        role: 'ANALYST',
        is_active: true,
        created_at: '2026-10-05T00:00:00Z',
        last_login_at: new Date().toISOString(),
      },
      {
        id: 'usr_auditor',
        email: 'auditor@sentinel.local',
        full_name: 'Security Compliance Auditor',
        role: 'VIEWER',
        is_active: true,
        created_at: '2026-10-10T00:00:00Z',
        last_login_at: new Date().toISOString(),
      },
    ]),
    create: (data: { email: string; password: string; full_name: string; role: string }) =>
      request<UserDetail>('/users', {
        method: 'POST',
        body: JSON.stringify(data),
      }, {
        id: `usr-${Date.now()}`,
        email: data.email,
        full_name: data.full_name,
        role: data.role as any,
        is_active: true,
        created_at: new Date().toISOString(),
      }),
  },

  audit: {
    list: () => request<AuditLogItem[]>('/audit-logs', {}, mockAuditLogs),
  },
};
