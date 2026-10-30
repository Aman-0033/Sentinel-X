import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertOctagon,
  Search,
  Filter,
  Download,
  ExternalLink,
  RefreshCw,
  SlidersHorizontal,
} from 'lucide-react';
import { Card, CardHeader } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Input } from '../components/ui/Input';
import { api } from '../services/api';
import { DetectionItem } from '../types';
import { formatDate, formatBytes } from '../utils/formatters';

export const Threats: React.FC = () => {
  const [detections, setDetections] = useState<DetectionItem[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [attackTypeFilter, setAttackTypeFilter] = useState('ALL');
  const [isLoading, setIsLoading] = useState(true);

  const loadDetections = async () => {
    setIsLoading(true);
    try {
      const data = await api.detections.list({
        severity: severityFilter !== 'ALL' ? severityFilter : undefined,
        attack_type: attackTypeFilter !== 'ALL' ? attackTypeFilter : undefined,
      });
      setDetections(data);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadDetections();
  }, [severityFilter, attackTypeFilter]);

  const filteredDetections = detections.filter((d) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      d.attack_type.toLowerCase().includes(term) ||
      d.flow?.source_ip.toLowerCase().includes(term) ||
      d.flow?.destination_ip.toLowerCase().includes(term) ||
      d.flow_id.toLowerCase().includes(term)
    );
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#1E293B]">
        <div>
          <h2 className="text-xl font-bold font-mono tracking-tight text-[#F8FAFC] flex items-center gap-2">
            <span>INTRUSION DETECTIONS & ANOMALIES</span>
          </h2>
          <p className="text-xs text-[#94A3B8] font-mono mt-0.5">
            Supervised attack classifications and unsupervised feature anomalies
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="secondary"
            size="sm"
            onClick={loadDetections}
            isLoading={isLoading}
            leftIcon={<RefreshCw className="w-3.5 h-3.5" />}
          >
            Refresh
          </Button>

          <Button
            variant="secondary"
            size="sm"
            onClick={() => {
              const csv =
                'data:text/csv;charset=utf-8,' +
                encodeURIComponent(
                  'ID,Timestamp,AttackType,Severity,SourceIP,DestIP,RiskScore\n' +
                    filteredDetections
                      .map(
                        (d) =>
                          `${d.id},${d.detected_at},${d.attack_type},${d.severity},${d.flow?.source_ip},${d.flow?.destination_ip},${d.risk_score}`
                      )
                      .join('\n')
                );
              const link = document.createElement('a');
              link.setAttribute('href', csv);
              link.setAttribute('download', `threats_export_${Date.now()}.csv`);
              document.body.appendChild(link);
              link.click();
              document.body.removeChild(link);
            }}
            leftIcon={<Download className="w-3.5 h-3.5" />}
          >
            Export CSV
          </Button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <Card className="p-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <div className="md:col-span-2">
            <Input
              placeholder="Search by IP, Flow ID, or Attack signature..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              leftIcon={<Search className="w-4 h-4 text-[#94A3B8]" />}
            />
          </div>

          <div>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="w-full bg-[#0A0A0A] border border-[#1E293B] rounded-lg px-3.5 py-2 text-sm text-[#F8FAFC] font-mono focus:border-[#007BA7] focus:outline-none"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          <div>
            <select
              value={attackTypeFilter}
              onChange={(e) => setAttackTypeFilter(e.target.value)}
              className="w-full bg-[#0A0A0A] border border-[#1E293B] rounded-lg px-3.5 py-2 text-sm text-[#F8FAFC] font-mono focus:border-[#007BA7] focus:outline-none"
            >
              <option value="ALL">All Attack Classes</option>
              <option value="DDoS">DDoS</option>
              <option value="PortScan">PortScan</option>
              <option value="BruteForce">BruteForce</option>
              <option value="Botnet">Botnet</option>
              <option value="SQLi">SQL Injection</option>
            </select>
          </div>
        </div>
      </Card>

      {/* Threats Table */}
      <Card>
        <CardHeader
          title={`Detected Threats (${filteredDetections.length})`}
          subtitle="Click any row or 'Triage' to inspect SHAP values and network telemetry"
          icon={<AlertOctagon className="w-5 h-5 text-[#007BA7]" />}
        />

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead>
              <tr className="border-b border-[#1E293B] text-[#94A3B8] uppercase text-[11px] tracking-wider">
                <th className="py-3 px-3">Severity</th>
                <th className="py-3 px-3">Classification</th>
                <th className="py-3 px-3">Source IP : Port</th>
                <th className="py-3 px-3">Destination IP : Port</th>
                <th className="py-3 px-3">Proto</th>
                <th className="py-3 px-3 text-right">Confidence</th>
                <th className="py-3 px-3 text-right">Risk Score</th>
                <th className="py-3 px-3">Timestamp</th>
                <th className="py-3 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B]/40">
              {filteredDetections.map((d) => (
                <tr
                  key={d.id}
                  className={`hover:bg-[#181822] transition-colors ${
                    d.severity === 'CRITICAL' ? 'bg-[#FF2D95]/5' : ''
                  }`}
                >
                  <td className="py-3 px-3 whitespace-nowrap">
                    <Badge severity={d.severity} showDot={d.severity === 'CRITICAL'}>
                      {d.severity}
                    </Badge>
                  </td>

                  <td className="py-3 px-3 whitespace-nowrap font-semibold text-white">
                    <div className="flex items-center gap-1.5">
                      <span>{d.attack_type}</span>
                      {d.is_anomaly && (
                        <span className="text-[9px] px-1 py-0.2 bg-[#FF2D95]/20 text-[#FF2D95] rounded border border-[#FF2D95]/30">
                          ANOMALY
                        </span>
                      )}
                    </div>
                  </td>

                  <td className="py-3 px-3 whitespace-nowrap text-[#F8FAFC]">
                    {d.flow?.source_ip}
                    <span className="text-[#94A3B8]">:{d.flow?.source_port}</span>
                  </td>

                  <td className="py-3 px-3 whitespace-nowrap text-gray-300">
                    {d.flow?.destination_ip}
                    <span className="text-[#94A3B8]">:{d.flow?.destination_port}</span>
                  </td>

                  <td className="py-3 px-3 text-[#94A3B8] whitespace-nowrap font-bold">
                    {d.flow?.protocol || 'TCP'}
                  </td>

                  <td className="py-3 px-3 text-right whitespace-nowrap text-[#007BA7] font-semibold">
                    {(d.confidence * 100).toFixed(1)}%
                  </td>

                  <td className="py-3 px-3 text-right whitespace-nowrap">
                    <span
                      className={`font-bold ${
                        d.risk_score >= 80
                          ? 'text-[#FF2D95]'
                          : d.risk_score >= 50
                          ? 'text-amber-400'
                          : 'text-[#007BA7]'
                      }`}
                    >
                      {d.risk_score}
                    </span>
                  </td>

                  <td className="py-3 px-3 text-[#94A3B8] whitespace-nowrap">
                    {formatDate(d.detected_at)}
                  </td>

                  <td className="py-3 px-3 text-right whitespace-nowrap">
                    <Link
                      to={`/threats/${d.id}`}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#121216] border border-[#1E293B] text-[#007BA7] hover:border-[#007BA7] hover:text-white transition-colors"
                    >
                      <span>Triage</span>
                      <ExternalLink className="w-3.5 h-3.5" />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};
