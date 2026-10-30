import React, { useState } from 'react';
import {
  Search,
  Globe,
  ShieldAlert,
  CheckCircle,
  ExternalLink,
  Layers,
  Database,
  RefreshCw,
} from 'lucide-react';
import { Card, CardHeader } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Input } from '../components/ui/Input';
import { RiskGauge } from '../components/charts/RiskGauge';
import { api } from '../services/api';
import { ThreatIntelData } from '../types';
import { formatDate } from '../utils/formatters';

export const ThreatIntelligence: React.FC = () => {
  const [indicatorInput, setIndicatorInput] = useState('198.51.100.42');
  const [indicatorType, setIndicatorType] = useState<'ip' | 'domain' | 'hash'>('ip');
  const [intelResult, setIntelResult] = useState<ThreatIntelData | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [recentQueries, setRecentQueries] = useState<ThreatIntelData[]>([
    {
      indicator: '198.51.100.42',
      indicator_type: 'ip',
      provider: 'VirusTotal & AbuseIPDB',
      reputation_score: 94,
      verdict: 'MALICIOUS',
      country: 'RU',
      asn: 'AS64496 (High-Risk Hosting)',
      checked_at: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
    },
    {
      indicator: '203.0.113.88',
      indicator_type: 'ip',
      provider: 'VirusTotal',
      reputation_score: 82,
      verdict: 'MALICIOUS',
      country: 'CN',
      asn: 'AS4134 (Chinanet)',
      checked_at: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
    },
    {
      indicator: '10.0.1.50',
      indicator_type: 'ip',
      provider: 'Sentinel Internal Allowlist',
      reputation_score: 0,
      verdict: 'CLEAN',
      country: 'US',
      asn: 'Private RFC 1918 Subnet',
      checked_at: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
    },
  ]);

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!indicatorInput.trim()) return;

    setIsLoading(true);
    try {
      const res = await api.threatIntel.enrich(indicatorInput.trim(), indicatorType);
      setIntelResult(res);

      // Add to recent queries
      setRecentQueries((prev) => [
        res,
        ...prev.filter((q) => q.indicator !== res.indicator).slice(0, 5),
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="pb-2 border-b border-[#1E293B]">
        <h2 className="text-xl font-bold font-mono tracking-tight text-[#F8FAFC] flex items-center gap-2">
          <span>THREAT INTELLIGENCE ENRICHMENT HUB</span>
        </h2>
        <p className="text-xs text-[#94A3B8] font-mono mt-0.5">
          Multi-provider reputation scoring, automated indicator verification, and ASN attribution
        </p>
      </div>

      {/* Lookup Form Card */}
      <Card>
        <CardHeader
          title="Query Indicator of Compromise (IOC)"
          subtitle="Enrich IP addresses, domains, or SHA-256 hashes against configured threat feeds"
          icon={<Search className="w-5 h-5 text-[#007BA7]" />}
        />

        <form onSubmit={handleLookup} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="md:col-span-3">
              <Input
                label="Indicator Value"
                required
                value={indicatorInput}
                onChange={(e) => setIndicatorInput(e.target.value)}
                placeholder="e.g. 198.51.100.42 or malware-c2-domain.com"
                leftIcon={<Globe className="w-4 h-4 text-[#94A3B8]" />}
              />
            </div>

            <div>
              <label className="block text-xs font-mono uppercase text-[#94A3B8] mb-1.5">
                Indicator Type
              </label>
              <select
                value={indicatorType}
                onChange={(e) => setIndicatorType(e.target.value as any)}
                className="w-full bg-[#0A0A0A] border border-[#1E293B] rounded-lg px-3.5 py-2 text-sm text-[#F8FAFC] font-mono focus:border-[#007BA7] focus:outline-none"
              >
                <option value="ip">IP Address</option>
                <option value="domain">Domain Name</option>
                <option value="hash">File Hash (SHA256)</option>
              </select>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <Button
              type="submit"
              variant="primary"
              size="md"
              isLoading={isLoading}
              leftIcon={<Search className="w-4 h-4" />}
            >
              Enrich Indicator
            </Button>
          </div>
        </form>
      </Card>

      {/* Lookup Result Display */}
      {intelResult && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-fade-in">
          {/* Posture & Verdict Card */}
          <Card className="flex flex-col items-center justify-center p-6 text-center">
            <h3 className="text-sm font-mono font-bold uppercase text-[#94A3B8] mb-2">
              Threat Intelligence Verdict
            </h3>
            <RiskGauge
              score={intelResult.reputation_score}
              title="Abuse Confidence"
              size={180}
              label="/ 100"
            />
            <div className="mt-4">
              <Badge
                severity={
                  intelResult.verdict === 'MALICIOUS'
                    ? 'CRITICAL'
                    : intelResult.verdict === 'SUSPICIOUS'
                    ? 'HIGH'
                    : 'BENIGN'
                }
                showDot
              >
                {intelResult.verdict}
              </Badge>
            </div>
          </Card>

          {/* Details Card */}
          <Card className="lg:col-span-2">
            <CardHeader
              title={`Reputation Details for: ${intelResult.indicator}`}
              subtitle={`Provider source: ${intelResult.provider}`}
              icon={<ShieldAlert className="w-5 h-5 text-[#FF2D95]" />}
            />

            <div className="grid grid-cols-2 gap-4 font-mono text-xs">
              <div className="p-3 bg-[#0A0A0A] border border-[#1E293B] rounded-lg">
                <span className="text-[#94A3B8] uppercase text-[10px]">Attributed ASN</span>
                <p className="text-white font-bold mt-0.5">{intelResult.asn || 'N/A'}</p>
              </div>

              <div className="p-3 bg-[#0A0A0A] border border-[#1E293B] rounded-lg">
                <span className="text-[#94A3B8] uppercase text-[10px]">Country Geolocation</span>
                <p className="text-white font-bold mt-0.5">{intelResult.country || 'Global / Unknown'}</p>
              </div>

              <div className="p-3 bg-[#0A0A0A] border border-[#1E293B] rounded-lg">
                <span className="text-[#94A3B8] uppercase text-[10px]">Last Checked</span>
                <p className="text-white font-bold mt-0.5">{formatDate(intelResult.checked_at)}</p>
              </div>

              <div className="p-3 bg-[#0A0A0A] border border-[#1E293B] rounded-lg">
                <span className="text-[#94A3B8] uppercase text-[10px]">Threat Provider Status</span>
                <p className="text-[#007BA7] font-bold mt-0.5">Enriched via Cache & API</p>
              </div>
            </div>

            {intelResult.response_data && (
              <div className="mt-4 p-3 bg-[#0A0A0A] border border-[#1E293B] rounded-lg text-xs font-mono">
                <span className="text-[#94A3B8] uppercase text-[10px] block mb-1">
                  Raw Provider Payload
                </span>
                <pre className="text-gray-300 text-[11px] overflow-x-auto">
                  {JSON.stringify(intelResult.response_data, null, 2)}
                </pre>
              </div>
            )}
          </Card>
        </div>
      )}

      {/* Recent Queries Table */}
      <Card>
        <CardHeader
          title="Recent Threat Queries & IOC Cache"
          subtitle="Cached indicator lookups across the security operations center"
          icon={<Database className="w-5 h-5 text-[#007BA7]" />}
        />
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead>
              <tr className="border-b border-[#1E293B] text-[#94A3B8] uppercase text-[11px]">
                <th className="py-2.5 px-3">Indicator</th>
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3">Verdict</th>
                <th className="py-2.5 px-3">Attributed ASN</th>
                <th className="py-2.5 px-3">Country</th>
                <th className="py-2.5 px-3 text-right">Reputation Score</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B]/40">
              {recentQueries.map((q) => (
                <tr key={q.indicator} className="hover:bg-[#181822] transition-colors">
                  <td className="py-2.5 px-3 text-white font-bold">{q.indicator}</td>
                  <td className="py-2.5 px-3 uppercase text-[#94A3B8]">{q.indicator_type}</td>
                  <td className="py-2.5 px-3">
                    <Badge
                      severity={
                        q.verdict === 'MALICIOUS'
                          ? 'CRITICAL'
                          : q.verdict === 'SUSPICIOUS'
                          ? 'HIGH'
                          : 'BENIGN'
                      }
                    >
                      {q.verdict}
                    </Badge>
                  </td>
                  <td className="py-2.5 px-3 text-gray-300">{q.asn || 'N/A'}</td>
                  <td className="py-2.5 px-3 text-gray-400">{q.country || 'Global'}</td>
                  <td className="py-2.5 px-3 text-right font-bold text-[#FF2D95]">
                    {q.reputation_score}
                  </td>
                  <td className="py-2.5 px-3 text-right">
                    <button
                      onClick={() => {
                        setIndicatorInput(q.indicator);
                        setIndicatorType(q.indicator_type);
                        setIntelResult(q);
                      }}
                      className="text-[#007BA7] hover:underline"
                    >
                      Inspect &rarr;
                    </button>
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
