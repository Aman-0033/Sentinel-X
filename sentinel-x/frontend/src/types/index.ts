// SENTINEL-X TypeScript Domain Models & API Schemas

export type UserRole = 'ADMIN' | 'ANALYST' | 'VIEWER';

export interface UserSummary {
  id: string;
  email: string;
  name: string;
  role: UserRole;
}

export interface UserDetail {
  id: string;
  email: string;
  full_name: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
  last_login_at?: string | null;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: UserSummary;
}

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'BENIGN';

export type AttackType =
  | 'Benign'
  | 'DDoS'
  | 'PortScan'
  | 'BruteForce'
  | 'Botnet'
  | 'Infiltration'
  | 'WebAttack'
  | 'Malware'
  | 'SQLi';

export interface FlowSummary {
  id: string;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  protocol: string;
  packets: number;
  bytes: number;
  duration_ms: number;
}

export interface ShapValue {
  feature: string;
  value: number;
  description?: string;
}

export interface DetectionItem {
  id: string;
  flow_id: string;
  model_version_id?: string | null;
  attack_type: string;
  confidence: number;
  anomaly_score?: number | null;
  risk_score: number;
  severity: SeverityLevel;
  is_anomaly: boolean;
  explanation?: {
    shap_values?: Record<string, number>;
    top_features?: Array<{ feature: string; impact: number }>;
    summary?: string;
  } | null;
  detected_at: string;
  flow?: FlowSummary | null;
}

export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';

export interface IncidentItem {
  id: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  status: IncidentStatus;
  assigned_to?: string | null;
  created_by?: string | null;
  created_at: string;
  updated_at: string;
  resolved_at?: string | null;
  detection_count: number;
}

export interface IncidentEvent {
  id: string;
  incident_id: string;
  event_type: string;
  message: string;
  metadata?: Record<string, unknown> | null;
  actor_id?: string | null;
  created_at: string;
}

export interface IncidentDetailData extends IncidentItem {
  detections: DetectionItem[];
  events: IncidentEvent[];
}

export interface DashboardSummaryData {
  active_threats: number;
  critical_threats: number;
  open_incidents: number;
  traffic_volume: number;
  security_score: number;
}

export interface TrendPoint {
  timestamp: string;
  count: number;
  severity: string;
  attack_type: string;
}

export interface AttackDistributionItem {
  attack_type: string;
  count: number;
  percentage: number;
}

export interface TopSourceItem {
  source_ip: string;
  attack_count: number;
  max_severity: SeverityLevel;
  max_risk_score: number;
}

export interface ThreatIntelData {
  indicator: string;
  indicator_type: 'ip' | 'domain' | 'hash';
  provider: string;
  reputation_score: number;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN';
  country?: string | null;
  asn?: string | null;
  checked_at: string;
  response_data?: Record<string, unknown> | null;
  error?: string | null;
}

export interface ModelVersionItem {
  id: string;
  name: string;
  version: string;
  algorithm: string;
  artifact_uri: string;
  status: 'ACTIVE' | 'CANDIDATE' | 'RETIRED';
  checksum: string;
  feature_schema?: Record<string, unknown> | null;
  metrics: {
    accuracy?: number;
    precision?: number;
    recall?: number;
    f1_score?: number;
    roc_auc?: number;
    [key: string]: number | undefined;
  };
  trained_at?: string | null;
  created_at: string;
}

export interface ReportItem {
  id: string;
  generated_by: string;
  incident_id?: string | null;
  period_start: string;
  period_end: string;
  format: 'PDF' | 'CSV' | 'JSON';
  file_path: string;
  status: 'PENDING' | 'GENERATED' | 'FAILED';
  created_at: string;
}

export interface AuditLogItem {
  id: string;
  user_id?: string | null;
  user_email?: string | null;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  ip_address: string;
  created_at: string;
  metadata?: Record<string, unknown> | null;
}

export interface ApiResponse<T> {
  data: T;
  meta: {
    request_id?: string;
    timestamp?: string;
  };
}

export interface PaginatedResponse<T> {
  data: T[];
  meta: {
    page: number;
    page_size: number;
    total: number;
    request_id?: string;
  };
}

export interface WebSocketTelemetryMessage {
  event: 'CONNECTED' | 'THREAT_DETECTED' | 'TELEMETRY_PULSE' | 'INCIDENT_CREATED' | 'HEARTBEAT';
  data: {
    message?: string;
    detection?: DetectionItem;
    packet_rate?: number;
    traffic_rate_mbps?: number;
    active_threats?: number;
    security_score?: number;
    timestamp?: string;
    [key: string]: unknown;
  };
}
