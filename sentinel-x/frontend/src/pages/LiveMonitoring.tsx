import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  Play,
  Pause,
  Trash2,
  Radio,
  Wifi,
  ExternalLink,
  Flame,
} from 'lucide-react';
import { Card, CardHeader } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { useTelemetry } from '../app/context/TelemetryContext';
import { formatDate, formatBytes } from '../utils/formatters';

export const LiveMonitoring: React.FC = () => {
  const {
    wsStatus,
    liveFeed,
    packetRate,
    trafficRateMbps,
    isPaused,
    togglePause,
    clearFeed,
  } = useTelemetry();

  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');

  const filteredFeed = liveFeed.filter((item) => {
    if (severityFilter !== 'ALL' && item.severity !== severityFilter) return false;
    if (protocolFilter !== 'ALL' && item.flow?.protocol !== protocolFilter) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header with live status and stream controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#1E293B]">
        <div>
          <h2 className="text-xl font-bold font-mono tracking-tight text-[#F8FAFC] flex items-center gap-2">
            <span>LIVE TELEMETRY & INTRUSION FEED</span>
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                wsStatus === 'CONNECTED' ? 'bg-[#007BA7] animate-ping' : 'bg-amber-400'
              }`}
            />
          </h2>
          <p className="text-xs text-[#94A3B8] font-mono mt-0.5">
            Streaming network flow packets and real-time ML anomaly alerts via WebSocket
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Button
            variant={isPaused ? 'primary' : 'secondary'}
            size="sm"
            onClick={togglePause}
            leftIcon={isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
          >
            {isPaused ? 'Resume Feed' : 'Pause Stream'}
          </Button>

          <Button
            variant="secondary"
            size="sm"
            onClick={clearFeed}
            leftIcon={<Trash2 className="w-3.5 h-3.5 text-[#FF2D95]" />}
          >
            Clear Log
          </Button>
        </div>
      </div>

      {/* Stream Metrics Banner */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-[#007BA7]/15 border border-[#007BA7]/40 flex items-center justify-center text-[#007BA7] shadow-glow-cerulean">
            <Radio className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="text-xs text-[#94A3B8] font-mono uppercase">Packet Throughput</div>
            <div className="text-2xl font-bold font-mono text-[#F8FAFC] mt-0.5">
              {packetRate.toLocaleString()} <span className="text-xs text-[#94A3B8]">pkts/sec</span>
            </div>
          </div>
        </Card>

        <Card className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-emerald-500/15 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
            <Wifi className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-[#94A3B8] font-mono uppercase">Network Ingress Rate</div>
            <div className="text-2xl font-bold font-mono text-[#F8FAFC] mt-0.5">
              {trafficRateMbps} <span className="text-xs text-[#94A3B8]">Mbps</span>
            </div>
          </div>
        </Card>

        <Card className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-[#FF2D95]/15 border border-[#FF2D95]/40 flex items-center justify-center text-[#FF2D95] shadow-glow-rose">
            <Flame className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs text-[#94A3B8] font-mono uppercase">Live Buffered Events</div>
            <div className="text-2xl font-bold font-mono text-[#FF2D95] mt-0.5">
              {liveFeed.length} <span className="text-xs text-[#94A3B8]">events</span>
            </div>
          </div>
        </Card>
      </div>

      {/* Real-time Streaming Table */}
      <Card>
        <CardHeader
          title="Streaming Telemetry Stream"
          subtitle={`Displaying ${filteredFeed.length} buffered flow items`}
          icon={<Activity className="w-5 h-5 text-[#007BA7]" />}
          action={
            <div className="flex items-center gap-2">
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-[#0A0A0A] border border-[#1E293B] rounded-lg px-2.5 py-1 text-xs text-[#F8FAFC] font-mono focus:border-[#007BA7] focus:outline-none"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical Only</option>
                <option value="HIGH">High Priority</option>
                <option value="MEDIUM">Medium Priority</option>
                <option value="BENIGN">Benign Only</option>
              </select>

              <select
                value={protocolFilter}
                onChange={(e) => setProtocolFilter(e.target.value)}
                className="bg-[#0A0A0A] border border-[#1E293B] rounded-lg px-2.5 py-1 text-xs text-[#F8FAFC] font-mono focus:border-[#007BA7] focus:outline-none"
              >
                <option value="ALL">All Protocols</option>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
              </select>
            </div>
          }
        />

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead>
              <tr className="border-b border-[#1E293B] text-[#94A3B8] uppercase text-[11px] tracking-wider">
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Classification</th>
                <th className="py-2.5 px-3">Source &rarr; Destination</th>
                <th className="py-2.5 px-3">Proto</th>
                <th className="py-2.5 px-3">Packets / Bytes</th>
                <th className="py-2.5 px-3 text-right">Risk Score</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B]/40">
              {filteredFeed.map((item) => {
                const isCritical = item.severity === 'CRITICAL';
                return (
                  <tr
                    key={item.id}
                    className={`hover:bg-[#181822] transition-colors ${
                      isCritical ? 'bg-[#FF2D95]/5' : ''
                    }`}
                  >
                    <td className="py-2.5 px-3 text-[#94A3B8] whitespace-nowrap">
                      {formatDate(item.detected_at)}
                    </td>

                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <Badge severity={item.severity} showDot={isCritical}>
                          {item.severity}
                        </Badge>
                        <span className="font-semibold text-white">{item.attack_type}</span>
                        {item.is_anomaly && (
                          <span className="text-[10px] px-1.5 py-0.2 bg-[#FF2D95]/20 text-[#FF2D95] rounded border border-[#FF2D95]/40 font-bold">
                            ANOMALY
                          </span>
                        )}
                      </div>
                    </td>

                    <td className="py-2.5 px-3 whitespace-nowrap text-[#F8FAFC]">
                      <span className="text-white font-medium">{item.flow?.source_ip}</span>
                      <span className="text-[#94A3B8] mx-1.5">&rarr;</span>
                      <span className="text-gray-300">
                        {item.flow?.destination_ip}:{item.flow?.destination_port}
                      </span>
                    </td>

                    <td className="py-2.5 px-3 text-[#94A3B8] whitespace-nowrap font-bold">
                      {item.flow?.protocol || 'TCP'}
                    </td>

                    <td className="py-2.5 px-3 text-[#94A3B8] whitespace-nowrap">
                      {item.flow?.packets?.toLocaleString()} pkts /{' '}
                      {formatBytes(item.flow?.bytes || 0)}
                    </td>

                    <td className="py-2.5 px-3 text-right whitespace-nowrap">
                      <span
                        className={`font-bold ${
                          item.risk_score >= 80
                            ? 'text-[#FF2D95]'
                            : item.risk_score >= 50
                            ? 'text-amber-400'
                            : 'text-[#007BA7]'
                        }`}
                      >
                        {item.risk_score}
                      </span>
                    </td>

                    <td className="py-2.5 px-3 text-right whitespace-nowrap">
                      <Link
                        to={`/threats/${item.id}`}
                        className="inline-flex items-center gap-1 text-[#007BA7] hover:text-white transition-colors"
                      >
                        <span>Investigate</span>
                        <ExternalLink className="w-3.5 h-3.5" />
                      </Link>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};
