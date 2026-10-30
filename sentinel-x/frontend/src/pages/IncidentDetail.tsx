import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft,
  ShieldAlert,
  Clock,
  User,
  Activity,
  Layers,
  Send,
  CheckCircle,
  FileText,
  AlertTriangle,
} from 'lucide-react';
import { Card, CardHeader } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { AttackGraph } from '../components/network/AttackGraph';
import { api } from '../services/api';
import { IncidentDetailData, IncidentStatus } from '../types';
import { formatDate } from '../utils/formatters';

export const IncidentDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [incident, setIncident] = useState<IncidentDetailData | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Status & Note state
  const [currentStatus, setCurrentStatus] = useState<IncidentStatus>('INVESTIGATING');
  const [noteText, setNoteText] = useState('');
  const [isSubmittingNote, setIsSubmittingNote] = useState(false);

  useEffect(() => {
    const fetchIncident = async () => {
      setIsLoading(true);
      try {
        const data = await api.incidents.getById(id || 'inc-2026-001');
        setIncident(data);
        setCurrentStatus(data.status);
      } finally {
        setIsLoading(false);
      }
    };

    fetchIncident();
  }, [id]);

  const handleStatusChange = async (newStatus: IncidentStatus) => {
    if (!incident) return;
    try {
      await api.incidents.updateStatus(incident.id, newStatus, `Analyst changed status to ${newStatus}`);
      setCurrentStatus(newStatus);
    } catch (e) {
      console.error(e);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!noteText.trim() || !incident) return;
    setIsSubmittingNote(true);
    try {
      await api.incidents.addEvent(incident.id, 'ANALYST_NOTE', noteText.trim());
      // Append note to UI
      const newEvent = {
        id: `ev-${Date.now()}`,
        incident_id: incident.id,
        event_type: 'ANALYST_NOTE',
        message: noteText.trim(),
        created_at: new Date().toISOString(),
      };
      setIncident({
        ...incident,
        events: [newEvent, ...incident.events],
      });
      setNoteText('');
    } finally {
      setIsSubmittingNote(false);
    }
  };

  if (isLoading || !incident) {
    return (
      <div className="py-20 text-center text-xs font-mono text-[#94A3B8]">
        Loading incident investigation data...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#1E293B]">
        <div className="flex items-center gap-3">
          <Link
            to="/incidents"
            className="p-2 rounded-lg bg-[#121216] border border-[#1E293B] text-[#94A3B8] hover:text-white transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-bold font-mono tracking-tight text-[#F8FAFC]">
                {incident.id}: {incident.title}
              </h2>
              <Badge severity={incident.severity} showDot>
                {incident.severity}
              </Badge>
            </div>
            <p className="text-xs text-[#94A3B8] font-mono mt-0.5">
              Created {formatDate(incident.created_at)} by {incident.created_by || 'SOC Automation'}
            </p>
          </div>
        </div>

        {/* Status Lifecycle Selector */}
        <div className="flex items-center gap-2">
          <label className="text-xs font-mono uppercase text-[#94A3B8]">Status:</label>
          <select
            value={currentStatus}
            onChange={(e) => handleStatusChange(e.target.value as IncidentStatus)}
            className="bg-[#121216] border border-[#007BA7] text-[#007BA7] font-mono font-bold text-xs rounded-lg px-3 py-1.5 focus:outline-none"
          >
            <option value="OPEN">OPEN</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="CONTAINED">CONTAINED</option>
            <option value="RESOLVED">RESOLVED</option>
            <option value="CLOSED">CLOSED</option>
          </select>
        </div>
      </div>

      {/* Incident Description & Metadata */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2">
          <CardHeader
            title="Incident Scope & Overview"
            subtitle="Incident summary and observed adversarial indicators"
            icon={<ShieldAlert className="w-5 h-5 text-[#FF2D95]" />}
          />
          <p className="text-sm text-[#F8FAFC] leading-relaxed font-sans">{incident.description}</p>

          <div className="mt-4 pt-4 border-t border-[#1E293B] grid grid-cols-3 gap-4 text-xs font-mono">
            <div>
              <span className="text-[#94A3B8] uppercase text-[10px]">Lead Assignee</span>
              <p className="text-white font-semibold mt-0.5">{incident.assigned_to || 'Unassigned'}</p>
            </div>
            <div>
              <span className="text-[#94A3B8] uppercase text-[10px]">Correlated Detections</span>
              <p className="text-[#007BA7] font-semibold mt-0.5">{incident.detections.length} flows</p>
            </div>
            <div>
              <span className="text-[#94A3B8] uppercase text-[10px]">SLA Target</span>
              <p className="text-emerald-400 font-semibold mt-0.5">Within 2h SLA</p>
            </div>
          </div>
        </Card>

        {/* Threat Intelligence Indicator Summary */}
        <Card>
          <CardHeader
            title="Associated Threat Intel"
            subtitle="External reputation check for primary indicator"
            icon={<Activity className="w-5 h-5 text-[#007BA7]" />}
          />
          <div className="space-y-3 font-mono text-xs">
            <div className="p-3 bg-[#0A0A0A] border border-[#1E293B] rounded-lg">
              <div className="flex items-center justify-between">
                <span className="text-white font-bold">198.51.100.42</span>
                <Badge severity="CRITICAL">MALICIOUS</Badge>
              </div>
              <p className="text-[11px] text-[#94A3B8] mt-1">VirusTotal Abuse Score: 94%</p>
              <p className="text-[10px] text-gray-400 mt-0.5">ASN: AS64496 (High-Risk Hosting)</p>
            </div>

            <Link
              to="/threat-intelligence"
              className="inline-flex items-center gap-1 text-xs text-[#007BA7] hover:underline"
            >
              Perform deep IOC query in Threat Intel hub &rarr;
            </Link>
          </div>
        </Card>
      </div>

      {/* Source-to-Target Attack Path Diagram */}
      <Card>
        <CardHeader
          title="Interactive Attack Path Diagram"
          subtitle="React Flow visual graph connecting external attacker, gateway, and targeted hosts"
          icon={<Layers className="w-5 h-5 text-[#007BA7]" />}
        />
        <AttackGraph
          sourceIp={incident.detections[0]?.flow?.source_ip || '198.51.100.42'}
          targetIp={incident.detections[0]?.flow?.destination_ip || '10.0.1.50'}
          attackType={incident.detections[0]?.attack_type || 'Distributed Intrusion'}
          height={320}
        />
      </Card>

      {/* Linked Detections Table */}
      <Card>
        <CardHeader
          title={`Correlated Detections (${incident.detections.length})`}
          subtitle="Telemetry flows linked to this incident by the automated correlation engine"
          icon={<Activity className="w-5 h-5 text-[#007BA7]" />}
        />
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead>
              <tr className="border-b border-[#1E293B] text-[#94A3B8] uppercase text-[11px]">
                <th className="py-2.5 px-3">Detection ID</th>
                <th className="py-2.5 px-3">Attack Class</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Source &rarr; Destination</th>
                <th className="py-2.5 px-3 text-right">Risk Score</th>
                <th className="py-2.5 px-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B]/40">
              {incident.detections.map((d) => (
                <tr key={d.id} className="hover:bg-[#181822] transition-colors">
                  <td className="py-2.5 px-3 text-[#94A3B8]">{d.id}</td>
                  <td className="py-2.5 px-3 font-semibold text-white">{d.attack_type}</td>
                  <td className="py-2.5 px-3">
                    <Badge severity={d.severity}>{d.severity}</Badge>
                  </td>
                  <td className="py-2.5 px-3 text-[#F8FAFC]">
                    {d.flow?.source_ip} &rarr; {d.flow?.destination_ip}
                  </td>
                  <td className="py-2.5 px-3 text-right font-bold text-[#FF2D95]">
                    {d.risk_score}
                  </td>
                  <td className="py-2.5 px-3 text-right">
                    <Link to={`/threats/${d.id}`} className="text-[#007BA7] hover:underline">
                      View SHAP &rarr;
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Attack Timeline & Analyst Comment Thread */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Timeline Log */}
        <Card>
          <CardHeader
            title="Attack Timeline & Event History"
            subtitle="Chronological log of triggers, status transitions, and actions"
            icon={<Clock className="w-5 h-5 text-[#007BA7]" />}
          />
          <div className="space-y-4 font-mono text-xs max-h-80 overflow-y-auto pr-2">
            {incident.events.map((ev) => (
              <div key={ev.id} className="flex items-start gap-3 relative pb-3 border-b border-[#1E293B]/40">
                <div className="w-2 h-2 rounded-full bg-[#007BA7] mt-1.5 shrink-0" />
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-[#F8FAFC]">{ev.event_type}</span>
                    <span className="text-[10px] text-[#94A3B8]">{formatDate(ev.created_at)}</span>
                  </div>
                  <p className="text-gray-300 mt-1 leading-relaxed">{ev.message}</p>
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* Add Analyst Note Form */}
        <Card>
          <CardHeader
            title="Append Analyst Note"
            subtitle="Add forensic observation or milestone to immutable incident timeline"
            icon={<FileText className="w-5 h-5 text-[#007BA7]" />}
          />
          <form onSubmit={handleAddNote} className="space-y-4">
            <textarea
              rows={4}
              required
              value={noteText}
              onChange={(e) => setNoteText(e.target.value)}
              placeholder="Record forensic observation, containment step, firewall block confirmation..."
              className="w-full bg-[#0A0A0A] border border-[#1E293B] rounded-lg p-3 text-xs text-[#F8FAFC] font-mono focus:border-[#007BA7] focus:outline-none"
            />
            <Button
              type="submit"
              variant="primary"
              size="sm"
              isLoading={isSubmittingNote}
              leftIcon={<Send className="w-3.5 h-3.5" />}
            >
              Post Timeline Note
            </Button>
          </form>
        </Card>
      </div>
    </div>
  );
};
