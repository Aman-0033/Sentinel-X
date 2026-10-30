import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldAlert,
  Flame,
  Activity,
  ArrowUpRight,
  TrendingUp,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
} from 'lucide-react';
import { Card, CardHeader } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { ThreatTimelineChart } from '../components/charts/ThreatTimelineChart';
import { AttackDistributionChart } from '../components/charts/AttackDistributionChart';
import { RiskGauge } from '../components/charts/RiskGauge';
import { api } from '../services/api';
import {
  DashboardSummaryData,
  TrendPoint,
  AttackDistributionItem,
  TopSourceItem,
  IncidentItem,
} from '../types';
import { formatBytes, formatDate } from '../utils/formatters';

export const Dashboard: React.FC = () => {
  const [summary, setSummary] = useState<DashboardSummaryData | null>(null);
  const [trends, setTrends] = useState<TrendPoint[]>([]);
  const [distribution, setDistribution] = useState<AttackDistributionItem[]>([]);
  const [topSources, setTopSources] = useState<TopSourceItem[]>([]);
  const [recentIncidents, setRecentIncidents] = useState<IncidentItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [sumRes, trendRes, distRes, topRes, incRes] = await Promise.all([
        api.dashboard.getSummary(),
        api.dashboard.getTrends(),
        api.dashboard.getAttackDistribution(),
        api.dashboard.getTopSources(5),
        api.incidents.list({ status: 'OPEN' }),
      ]);
      setSummary(sumRes);
      setTrends(trendRes);
      setDistribution(distRes);
      setTopSources(topRes);
      setRecentIncidents(incRes.slice(0, 4));
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  return (
    <div className="space-y-6">
      {/* Top Banner & Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#1E293B]">
        <div>
          <h2 className="text-xl font-bold font-mono tracking-tight text-[#F8FAFC] flex items-center gap-2">
            <span>SOC OVERVIEW & THREAT POSTURE</span>
            <span className="w-2 h-2 rounded-full bg-[#007BA7] animate-ping" />
          </h2>
          <p className="text-xs text-[#94A3B8] font-mono mt-0.5">
            Real-time heuristic threat detection and automated incident correlation
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="secondary"
            size="sm"
            onClick={loadData}
            isLoading={isLoading}
            leftIcon={<RefreshCw className="w-3.5 h-3.5" />}
          >
            Refresh Telemetry
          </Button>

          <Link to="/live-monitoring">
            <Button
              variant="primary"
              size="sm"
              rightIcon={<ArrowUpRight className="w-3.5 h-3.5" />}
            >
              Live Telemetry Feed
            </Button>
          </Link>
        </div>
      </div>

      {/* 4 Core KPI Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* KPI 1: Active Threats */}
        <Card glow={summary && summary.active_threats > 0 ? 'rose' : 'none'}>
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-mono uppercase tracking-wider text-[#94A3B8]">
                Active Threats (24h)
              </p>
              <h3 className="text-3xl font-extrabold font-mono text-[#F8FAFC] mt-1.5">
                {summary?.active_threats ?? '—'}
              </h3>
              <p className="text-[11px] text-[#FF2D95] font-mono mt-1 flex items-center gap-1 font-semibold">
                <Flame className="w-3.5 h-3.5 text-[#FF2D95]" />
                <span>Malicious signatures detected</span>
              </p>
            </div>
            <div className="w-10 h-10 rounded-xl bg-[#FF2D95]/15 border border-[#FF2D95]/30 flex items-center justify-center text-[#FF2D95]">
              <ShieldAlert className="w-5 h-5" />
            </div>
          </div>
        </Card>

        {/* KPI 2: Critical Severity Count */}
        <Card glow={summary && summary.critical_threats > 0 ? 'rose' : 'none'}>
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-mono uppercase tracking-wider text-[#94A3B8]">
                Critical Priority
              </p>
              <h3 className="text-3xl font-extrabold font-mono text-[#FF2D95] mt-1.5">
                {summary?.critical_threats ?? '—'}
              </h3>
              <p className="text-[11px] text-[#94A3B8] font-mono mt-1">
                Immediate SOC triage required
              </p>
            </div>
            <div className="w-10 h-10 rounded-xl bg-[#FF2D95]/20 border border-[#FF2D95]/40 flex items-center justify-center text-[#FF2D95]">
              <AlertTriangle className="w-5 h-5" />
            </div>
          </div>
        </Card>

        {/* KPI 3: Open Incidents */}
        <Card>
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-mono uppercase tracking-wider text-[#94A3B8]">
                Open Incidents
              </p>
              <h3 className="text-3xl font-extrabold font-mono text-[#F8FAFC] mt-1.5">
                {summary?.open_incidents ?? '—'}
              </h3>
              <p className="text-[11px] text-[#007BA7] font-mono mt-1 font-semibold">
                Under active investigation
              </p>
            </div>
            <div className="w-10 h-10 rounded-xl bg-[#007BA7]/15 border border-[#007BA7]/30 flex items-center justify-center text-[#007BA7]">
              <TrendingUp className="w-5 h-5" />
            </div>
          </div>
        </Card>

        {/* KPI 4: Ingested Traffic */}
        <Card>
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-mono uppercase tracking-wider text-[#94A3B8]">
                Telemetry Flows
              </p>
              <h3 className="text-3xl font-extrabold font-mono text-[#F8FAFC] mt-1.5">
                {summary ? summary.traffic_volume.toLocaleString() : '—'}
              </h3>
              <p className="text-[11px] text-emerald-400 font-mono mt-1 font-semibold">
                Normal throughput
              </p>
            </div>
            <div className="w-10 h-10 rounded-xl bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <Activity className="w-5 h-5" />
            </div>
          </div>
        </Card>
      </div>

      {/* Main Grid: Charts & Posture */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Timeline (2 cols) */}
        <Card className="lg:col-span-2">
          <CardHeader
            title="Threat Timeline & Anomaly Spikes"
            subtitle="Hourly detection frequency with Cerulean baseline & Neon Rose spikes"
            icon={<Activity className="w-5 h-5" />}
          />
          <ThreatTimelineChart data={trends} height={260} />
        </Card>

        {/* Security Posture Gauge (1 col) */}
        <Card className="flex flex-col items-center justify-center">
          <CardHeader
            title="Security Posture Index"
            subtitle="Heuristic 0-100 composite defense score"
            className="w-full text-center"
          />
          <div className="my-2">
            <RiskGauge
              score={summary?.security_score ?? 84}
              title="Global Health"
              size={200}
            />
          </div>
          <div className="w-full mt-4 pt-3 border-t border-[#1E293B] text-center text-xs text-[#94A3B8] font-mono">
            Penalty: -10 for Critical, -5 for Open Incident
          </div>
        </Card>
      </div>

      {/* Bottom Grid: Attack Distribution, Top Suspicious IPs, Recent Incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Attack Category Breakdown */}
        <Card>
          <CardHeader
            title="Attack Classification Breakdown"
            subtitle="Categorized by supervised ML inference"
          />
          <AttackDistributionChart data={distribution} height={210} />
          <div className="mt-4 space-y-1.5 max-h-36 overflow-y-auto pr-1">
            {distribution.map((item) => (
              <div
                key={item.attack_type}
                className="flex items-center justify-between text-xs font-mono py-1 border-b border-[#1E293B]/40"
              >
                <span className="text-[#F8FAFC]">{item.attack_type}</span>
                <span className="text-[#94A3B8]">
                  <strong className="text-white">{item.count}</strong> ({item.percentage}%)
                </span>
              </div>
            ))}
          </div>
        </Card>

        {/* Top Suspicious Source IPs */}
        <Card>
          <CardHeader
            title="Top Adversarial IP Addresses"
            subtitle="Ranked by volume and risk severity"
            action={
              <Link to="/threat-intelligence" className="text-xs text-[#007BA7] hover:underline font-mono">
                Lookup IOC
              </Link>
            }
          />
          <div className="space-y-3">
            {topSources.map((src) => (
              <div
                key={src.source_ip}
                className="flex items-center justify-between p-2.5 bg-[#0A0A0A] border border-[#1E293B] rounded-lg hover:border-[#007BA7]/40 transition-colors"
              >
                <div>
                  <div className="text-xs font-mono font-bold text-[#F8FAFC] flex items-center gap-2">
                    <span>{src.source_ip}</span>
                    <Badge severity={src.max_severity} variant="subtle">
                      {src.max_severity}
                    </Badge>
                  </div>
                  <div className="text-[10px] text-[#94A3B8] font-mono mt-0.5">
                    {src.attack_count} malicious flow detections
                  </div>
                </div>

                <div className="text-right">
                  <div className="text-xs font-mono font-bold text-[#FF2D95]">
                    {src.max_risk_score}
                  </div>
                  <div className="text-[9px] text-[#94A3B8] font-mono uppercase">Risk Score</div>
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* Recent Incidents */}
        <Card>
          <CardHeader
            title="Active Security Incidents"
            subtitle="Correlated multi-event investigations"
            action={
              <Link to="/incidents" className="text-xs text-[#007BA7] hover:underline font-mono">
                View All
              </Link>
            }
          />
          <div className="space-y-3">
            {recentIncidents.map((inc) => (
              <Link
                key={inc.id}
                to={`/incidents/${inc.id}`}
                className="block p-3 bg-[#0A0A0A] border border-[#1E293B] hover:border-[#007BA7] rounded-lg transition-colors group"
              >
                <div className="flex items-start justify-between gap-2">
                  <span className="text-xs font-semibold text-[#F8FAFC] group-hover:text-[#007BA7] transition-colors line-clamp-1">
                    {inc.title}
                  </span>
                  <Badge severity={inc.severity} variant="subtle">
                    {inc.severity}
                  </Badge>
                </div>
                <div className="flex items-center justify-between text-[11px] text-[#94A3B8] font-mono mt-2 pt-2 border-t border-[#1E293B]/40">
                  <span>{inc.assigned_to || 'Unassigned'}</span>
                  <span>{formatDate(inc.created_at)}</span>
                </div>
              </Link>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
};
