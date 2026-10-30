import React, { useEffect, useState } from 'react';
import {
  ClipboardList,
  Search,
  ShieldCheck,
  Lock,
  Download,
  RefreshCw,
  FileText,
} from 'lucide-react';
import { Card, CardHeader } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Input } from '../components/ui/Input';
import { api } from '../services/api';
import { AuditLogItem } from '../types';
import { formatDate } from '../utils/formatters';

export const AuditLogs: React.FC = () => {
  const [logs, setLogs] = useState<AuditLogItem[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [isLoading, setIsLoading] = useState(true);

  const loadAuditLogs = async () => {
    setIsLoading(true);
    try {
      const data = await api.audit.list();
      setLogs(data);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadAuditLogs();
  }, []);

  const filteredLogs = logs.filter((l) => {
    if (actionFilter !== 'ALL' && l.action !== actionFilter) return false;
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      l.action.toLowerCase().includes(term) ||
      (l.user_email && l.user_email.toLowerCase().includes(term)) ||
      l.resource_type.toLowerCase().includes(term) ||
      l.ip_address.toLowerCase().includes(term)
    );
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#1E293B]">
        <div>
          <h2 className="text-xl font-bold font-mono tracking-tight text-[#F8FAFC] flex items-center gap-2">
            <span>SECURITY AUDIT TRAIL & COMPLIANCE LOGS</span>
          </h2>
          <p className="text-xs text-[#94A3B8] font-mono mt-0.5">
            Immutable chronological record of administrative actions, credential lifecycle, and model promotions
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="secondary"
            size="sm"
            onClick={loadAuditLogs}
            isLoading={isLoading}
            leftIcon={<RefreshCw className="w-3.5 h-3.5" />}
          >
            Refresh
          </Button>

          <Button
            variant="secondary"
            size="sm"
            onClick={() => {
              const content = JSON.stringify(filteredLogs, null, 2);
              const blob = new Blob([content], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = `sentinel_audit_logs_${Date.now()}.json`;
              document.body.appendChild(a);
              a.click();
              document.body.removeChild(a);
            }}
            leftIcon={<Download className="w-3.5 h-3.5" />}
          >
            Export JSON
          </Button>
        </div>
      </div>

      {/* Secret Redaction Banner */}
      <div className="p-3 bg-[#007BA7]/10 border border-[#007BA7]/30 rounded-lg flex items-center justify-between text-xs font-mono text-[#007BA7]">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 shrink-0" />
          <span>
            IMMUTABLE SECURITY INTEGRITY: Passwords, tokens, and authorization secrets are strictly redacted before emission.
          </span>
        </div>
        <div className="flex items-center gap-1.5 text-emerald-400">
          <Lock className="w-3.5 h-3.5" />
          <span>ZERO SECRET LEAKAGE</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <Card className="p-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div className="md:col-span-2">
            <Input
              placeholder="Search by action, operator email, or resource..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              leftIcon={<Search className="w-4 h-4 text-[#94A3B8]" />}
            />
          </div>

          <div>
            <select
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              className="w-full bg-[#0A0A0A] border border-[#1E293B] rounded-lg px-3.5 py-2 text-sm text-[#F8FAFC] font-mono focus:border-[#007BA7] focus:outline-none"
            >
              <option value="ALL">All Actions</option>
              <option value="USER_LOGIN">USER_LOGIN</option>
              <option value="MODEL_ACTIVATE">MODEL_ACTIVATE</option>
              <option value="INCIDENT_UPDATE_STATUS">INCIDENT_UPDATE_STATUS</option>
              <option value="REPORT_GENERATE">REPORT_GENERATE</option>
            </select>
          </div>
        </div>
      </Card>

      {/* Audit Log Table */}
      <Card>
        <CardHeader
          title={`Audit Records (${filteredLogs.length})`}
          subtitle="Non-repudiable log entries stored in append-only schema"
          icon={<ClipboardList className="w-5 h-5 text-[#007BA7]" />}
        />

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead>
              <tr className="border-b border-[#1E293B] text-[#94A3B8] uppercase text-[11px]">
                <th className="py-3 px-3">Timestamp</th>
                <th className="py-3 px-3">Operator Email</th>
                <th className="py-3 px-3">Action</th>
                <th className="py-3 px-3">Target Resource</th>
                <th className="py-3 px-3">Client IP</th>
                <th className="py-3 px-3">Audit Metadata & Redaction</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B]/40">
              {filteredLogs.map((log) => (
                <tr key={log.id} className="hover:bg-[#181822] transition-colors">
                  <td className="py-3 px-3 text-[#94A3B8] whitespace-nowrap">
                    {formatDate(log.created_at)}
                  </td>

                  <td className="py-3 px-3 text-white font-semibold whitespace-nowrap">
                    {log.user_email || 'System Daemon'}
                  </td>

                  <td className="py-3 px-3 whitespace-nowrap">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        log.action.includes('ACTIVATE')
                          ? 'bg-[#FF2D95]/15 text-[#FF2D95] border border-[#FF2D95]/30'
                          : log.action.includes('LOGIN')
                          ? 'bg-[#007BA7]/15 text-[#007BA7] border border-[#007BA7]/30'
                          : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                      }`}
                    >
                      {log.action}
                    </span>
                  </td>

                  <td className="py-3 px-3 text-gray-300 whitespace-nowrap">
                    <span className="text-[#94A3B8]">{log.resource_type}:</span> {log.resource_id}
                  </td>

                  <td className="py-3 px-3 text-gray-400 whitespace-nowrap">{log.ip_address}</td>

                  <td className="py-3 px-3 text-gray-400">
                    <pre className="text-[10px] text-gray-400 bg-[#0A0A0A] p-1.5 rounded border border-[#1E293B] inline-block max-w-xs truncate">
                      {JSON.stringify(log.metadata || {})}
                    </pre>
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
