import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  FolderLock,
  Plus,
  Search,
  Filter,
  Clock,
  User,
  ShieldAlert,
  ArrowRight,
  RefreshCw,
} from 'lucide-react';
import { Card, CardHeader } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Input } from '../components/ui/Input';
import { Modal } from '../components/ui/Modal';
import { api } from '../services/api';
import { IncidentItem, IncidentStatus } from '../types';
import { formatDate } from '../utils/formatters';

export const Incidents: React.FC = () => {
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [isLoading, setIsLoading] = useState(true);

  // New incident modal
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newSeverity, setNewSeverity] = useState('HIGH');

  const loadIncidents = async () => {
    setIsLoading(true);
    try {
      const data = await api.incidents.list({
        status: statusFilter !== 'ALL' ? statusFilter : undefined,
        severity: severityFilter !== 'ALL' ? severityFilter : undefined,
      });
      setIncidents(data);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, [statusFilter, severityFilter]);

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;

    const created: IncidentItem = {
      id: `inc-2026-${String(incidents.length + 1).padStart(3, '0')}`,
      title: newTitle.trim(),
      description: newDescription.trim(),
      severity: newSeverity as any,
      status: 'OPEN',
      assigned_to: 'Security Administrator',
      created_by: 'Manual Escalation',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      detection_count: 1,
    };

    setIncidents([created, ...incidents]);
    setIsModalOpen(false);
    setNewTitle('');
    setNewDescription('');
  };

  const filteredIncidents = incidents.filter((inc) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      inc.title.toLowerCase().includes(term) ||
      inc.description.toLowerCase().includes(term) ||
      (inc.assigned_to && inc.assigned_to.toLowerCase().includes(term))
    );
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#1E293B]">
        <div>
          <h2 className="text-xl font-bold font-mono tracking-tight text-[#F8FAFC] flex items-center gap-2">
            <span>SECURITY INCIDENTS & ESCALATIONS</span>
          </h2>
          <p className="text-xs text-[#94A3B8] font-mono mt-0.5">
            Correlated multi-vector intrusions and containment lifecycle tracking
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="secondary"
            size="sm"
            onClick={loadIncidents}
            isLoading={isLoading}
            leftIcon={<RefreshCw className="w-3.5 h-3.5" />}
          >
            Refresh
          </Button>

          <Button
            variant="primary"
            size="sm"
            onClick={() => setIsModalOpen(true)}
            leftIcon={<Plus className="w-3.5 h-3.5" />}
          >
            Create Incident
          </Button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <Card className="p-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <div className="md:col-span-2">
            <Input
              placeholder="Search incidents by title, description, or analyst..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              leftIcon={<Search className="w-4 h-4 text-[#94A3B8]" />}
            />
          </div>

          <div>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full bg-[#0A0A0A] border border-[#1E293B] rounded-lg px-3.5 py-2 text-sm text-[#F8FAFC] font-mono focus:border-[#007BA7] focus:outline-none"
            >
              <option value="ALL">All Statuses</option>
              <option value="OPEN">OPEN</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="CONTAINED">CONTAINED</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="CLOSED">CLOSED</option>
            </select>
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
        </div>
      </Card>

      {/* Incident Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredIncidents.map((inc) => (
          <Card
            key={inc.id}
            glow={inc.severity === 'CRITICAL' ? 'rose' : 'none'}
            interactive
            className="flex flex-col justify-between"
          >
            <div>
              <div className="flex items-start justify-between gap-3 mb-2">
                <span className="text-xs font-mono font-bold text-[#007BA7]">{inc.id}</span>
                <div className="flex items-center gap-2">
                  <Badge severity={inc.severity} showDot={inc.severity === 'CRITICAL'}>
                    {inc.severity}
                  </Badge>
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                      inc.status === 'OPEN'
                        ? 'border-[#FF2D95]/40 text-[#FF2D95] bg-[#FF2D95]/10'
                        : inc.status === 'INVESTIGATING'
                        ? 'border-amber-500/40 text-amber-400 bg-amber-500/10'
                        : 'border-emerald-500/40 text-emerald-400 bg-emerald-500/10'
                    }`}
                  >
                    {inc.status}
                  </span>
                </div>
              </div>

              <h3 className="text-base font-semibold text-[#F8FAFC] mb-1.5">{inc.title}</h3>
              <p className="text-xs text-[#94A3B8] leading-relaxed line-clamp-2">{inc.description}</p>
            </div>

            <div className="mt-4 pt-3 border-t border-[#1E293B] flex items-center justify-between text-xs font-mono text-[#94A3B8]">
              <div className="flex items-center gap-4">
                <span className="flex items-center gap-1.5">
                  <User className="w-3.5 h-3.5 text-[#007BA7]" />
                  <span>{inc.assigned_to || 'Unassigned'}</span>
                </span>
                <span className="flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-[#FF2D95]" />
                  <span>{inc.detection_count} detections</span>
                </span>
              </div>

              <Link
                to={`/incidents/${inc.id}`}
                className="inline-flex items-center gap-1 text-[#007BA7] hover:text-white font-semibold transition-colors"
              >
                <span>Investigate</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            </div>
          </Card>
        ))}
      </div>

      {/* Modal: Create Incident */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title="Escalate New Security Incident"
        description="Bind correlated telemetry detections to a formal SOC incident"
      >
        <form onSubmit={handleCreateIncident} className="space-y-4">
          <Input
            label="Incident Title"
            required
            value={newTitle}
            onChange={(e) => setNewTitle(e.target.value)}
            placeholder="e.g. Distributed SYN Flood targeting DB cluster"
          />

          <div>
            <label className="block text-xs font-mono uppercase text-[#94A3B8] mb-1.5">
              Severity Level
            </label>
            <select
              value={newSeverity}
              onChange={(e) => setNewSeverity(e.target.value)}
              className="w-full bg-[#0A0A0A] border border-[#1E293B] rounded-lg px-3.5 py-2 text-sm text-[#F8FAFC] font-mono focus:border-[#007BA7] focus:outline-none"
            >
              <option value="CRITICAL">CRITICAL (System Impairment)</option>
              <option value="HIGH">HIGH (Adversarial Recon / Exploit)</option>
              <option value="MEDIUM">MEDIUM (Suspicious Activity)</option>
              <option value="LOW">LOW (Informational Anomaly)</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-mono uppercase text-[#94A3B8] mb-1.5">
              Description & Indicators
            </label>
            <textarea
              required
              rows={3}
              value={newDescription}
              onChange={(e) => setNewDescription(e.target.value)}
              placeholder="Outline the observed threat vectors, affected IP subnets, and urgency..."
              className="w-full bg-[#0A0A0A] border border-[#1E293B] rounded-lg p-3 text-sm text-[#F8FAFC] font-mono focus:border-[#007BA7] focus:outline-none"
            />
          </div>

          <div className="flex items-center justify-end gap-3 pt-2">
            <Button variant="ghost" size="sm" type="button" onClick={() => setIsModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" size="sm" type="submit">
              Escalate Incident
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
