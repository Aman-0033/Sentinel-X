import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft,
  ShieldAlert,
  Server,
  Cpu,
  Activity,
  CheckCircle,
  XCircle,
  FolderLock,
  Layers,
  Send,
} from 'lucide-react';
import { Card, CardHeader } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { ShapBarChart } from '../components/charts/ShapBarChart';
import { AttackGraph } from '../components/network/AttackGraph';
import { api } from '../services/api';
import { DetectionItem } from '../types';
import { formatDate, formatBytes } from '../utils/formatters';

export const ThreatDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [detection, setDetection] = useState<DetectionItem | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Analyst feedback form state
  const [feedbackSuccess, setFeedbackSuccess] = useState(false);
  const [notes, setNotes] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    const fetchDetection = async () => {
      setIsLoading(true);
      try {
        const data = await api.detections.getById(id || 'det-001-synflood');
        setDetection(data);
      } finally {
        setIsLoading(false);
      }
    };

    fetchDetection();
  }, [id]);

  const handleFeedback = async (isCorrect: boolean) => {
    if (!detection) return;
    setIsSubmitting(true);
    try {
      await api.detections.submitFeedback(detection.id, {
        is_correct: isCorrect,
        notes,
      });
      setFeedbackSuccess(true);
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isLoading || !detection) {
    return (
      <div className="py-20 text-center text-xs font-mono text-[#94A3B8]">
        Loading forensic threat telemetry...
      </div>
    );
  }

  // Generate top features for SHAP chart
  const shapFeatures =
    detection.explanation?.top_features || [
      { feature: 'syn_flag_count', impact: 0.42 },
      { feature: 'packet_rate_per_sec', impact: 0.31 },
      { feature: 'flow_duration_ms', impact: 0.12 },
      { feature: 'destination_port_entropy', impact: 0.08 },
      { feature: 'fwd_packet_length_mean', impact: -0.15 },
    ];

  return (
    <div className="space-y-6">
      {/* Back button and Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#1E293B]">
        <div className="flex items-center gap-3">
          <Link
            to="/threats"
            className="p-2 rounded-lg bg-[#121216] border border-[#1E293B] text-[#94A3B8] hover:text-white transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-bold font-mono tracking-tight text-[#F8FAFC]">
                THREAT FORENSICS: {detection.id}
              </h2>
              <Badge severity={detection.severity} showDot>
                {detection.severity}
              </Badge>
            </div>
            <p className="text-xs text-[#94A3B8] font-mono mt-0.5">
              Flow ID: {detection.flow_id} • Detected {formatDate(detection.detected_at)}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Link to={`/incidents`}>
            <Button
              variant="secondary"
              size="sm"
              leftIcon={<FolderLock className="w-3.5 h-3.5 text-[#007BA7]" />}
            >
              Correlate to Incident
            </Button>
          </Link>
        </div>
      </div>

      {/* Grid: Flow Metadata & Risk Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Network Flow Telemetry Card */}
        <Card className="lg:col-span-2">
          <CardHeader
            title="Ingested Network Flow Parameters"
            subtitle="Raw packet attributes captured from network telemetry"
            icon={<Server className="w-5 h-5 text-[#007BA7]" />}
          />
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 font-mono text-xs">
            <div className="p-3 bg-[#0A0A0A] border border-[#1E293B] rounded-lg">
              <span className="text-[#94A3B8] uppercase text-[10px]">Source IP</span>
              <p className="text-white font-bold text-sm mt-0.5">{detection.flow?.source_ip}</p>
              <span className="text-gray-400 text-[10px]">Port {detection.flow?.source_port}</span>
            </div>

            <div className="p-3 bg-[#0A0A0A] border border-[#1E293B] rounded-lg">
              <span className="text-[#94A3B8] uppercase text-[10px]">Destination IP</span>
              <p className="text-white font-bold text-sm mt-0.5">{detection.flow?.destination_ip}</p>
              <span className="text-gray-400 text-[10px]">Port {detection.flow?.destination_port}</span>
            </div>

            <div className="p-3 bg-[#0A0A0A] border border-[#1E293B] rounded-lg">
              <span className="text-[#94A3B8] uppercase text-[10px]">Transport Protocol</span>
              <p className="text-[#007BA7] font-bold text-sm mt-0.5">{detection.flow?.protocol || 'TCP'}</p>
              <span className="text-gray-400 text-[10px]">IP Header Ver 4</span>
            </div>

            <div className="p-3 bg-[#0A0A0A] border border-[#1E293B] rounded-lg">
              <span className="text-[#94A3B8] uppercase text-[10px]">Flow Duration</span>
              <p className="text-white font-bold text-sm mt-0.5">{detection.flow?.duration_ms} ms</p>
              <span className="text-gray-400 text-[10px]">Bidirectional</span>
            </div>

            <div className="p-3 bg-[#0A0A0A] border border-[#1E293B] rounded-lg">
              <span className="text-[#94A3B8] uppercase text-[10px]">Packets Ingested</span>
              <p className="text-white font-bold text-sm mt-0.5">{detection.flow?.packets?.toLocaleString()} pkts</p>
              <span className="text-gray-400 text-[10px]">Forward + Backward</span>
            </div>

            <div className="p-3 bg-[#0A0A0A] border border-[#1E293B] rounded-lg">
              <span className="text-[#94A3B8] uppercase text-[10px]">Payload Volume</span>
              <p className="text-white font-bold text-sm mt-0.5">{formatBytes(detection.flow?.bytes || 0)}</p>
              <span className="text-gray-400 text-[10px]">Total Bytes</span>
            </div>
          </div>
        </Card>

        {/* AI Model Risk Engine Card */}
        <Card>
          <CardHeader
            title="Model Inference & Risk Engine"
            subtitle="Deterministic multi-factor risk output"
            icon={<Cpu className="w-5 h-5 text-[#FF2D95]" />}
          />
          <div className="space-y-4 font-mono text-xs">
            <div className="p-3 bg-[#0A0A0A] border border-[#1E293B] rounded-lg flex items-center justify-between">
              <div>
                <span className="text-[#94A3B8] uppercase text-[10px]">Classified Threat</span>
                <p className="text-white font-bold text-sm mt-0.5">{detection.attack_type}</p>
              </div>
              <div className="text-right">
                <span className="text-[#94A3B8] uppercase text-[10px]">Confidence</span>
                <p className="text-[#007BA7] font-bold text-sm mt-0.5">
                  {(detection.confidence * 100).toFixed(1)}%
                </p>
              </div>
            </div>

            <div className="p-3 bg-[#0A0A0A] border border-[#1E293B] rounded-lg flex items-center justify-between">
              <div>
                <span className="text-[#94A3B8] uppercase text-[10px]">Anomaly Score (IForest)</span>
                <p className="text-white font-bold text-sm mt-0.5">
                  {detection.anomaly_score !== null ? detection.anomaly_score : 'N/A'}
                </p>
              </div>
              <Badge severity={detection.is_anomaly ? 'CRITICAL' : 'BENIGN'}>
                {detection.is_anomaly ? 'ANOMALY DETECTED' : 'WITHIN BOUNDS'}
              </Badge>
            </div>

            <div className="p-3 bg-[#0A0A0A] border border-[#1E293B] rounded-lg flex items-center justify-between">
              <div>
                <span className="text-[#94A3B8] uppercase text-[10px]">Deterministic Risk</span>
                <p className="text-[#FF2D95] font-extrabold text-lg mt-0.5">{detection.risk_score} / 100</p>
              </div>
              <div className="text-right">
                <span className="text-[#94A3B8] uppercase text-[10px]">Calculated Severity</span>
                <p className="text-white font-bold mt-0.5">{detection.severity}</p>
              </div>
            </div>
          </div>
        </Card>
      </div>

      {/* SHAP Feature Explainability Section */}
      <Card>
        <CardHeader
          title="SHAP Feature Explainability (XAI)"
          subtitle="Top contributing flow metrics pushing the prediction toward malicious (#FF2D95) vs benign (#007BA7)"
          icon={<Layers className="w-5 h-5 text-[#007BA7]" />}
        />
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <ShapBarChart features={shapFeatures} height={250} />
          </div>

          <div className="p-4 bg-[#0A0A0A] border border-[#1E293B] rounded-xl flex flex-col justify-between font-mono text-xs">
            <div>
              <div className="flex items-center gap-2 text-white font-semibold mb-2">
                <ShieldAlert className="w-4 h-4 text-[#FF2D95]" />
                <span>Explanation Summary</span>
              </div>
              <p className="text-[#94A3B8] leading-relaxed">
                {detection.explanation?.summary ||
                  'High frequency of SYN packets combined with abnormally short flow duration strongly contributed to the DDoS classification.'}
              </p>
            </div>

            <div className="mt-4 pt-3 border-t border-[#1E293B] flex items-center justify-between text-[11px] text-[#94A3B8]">
              <span>Active Model Bundle:</span>
              <span className="text-[#007BA7] font-semibold">XGBoost v1.2.0</span>
            </div>
          </div>
        </div>
      </Card>

      {/* Attack Graph Visualization */}
      <Card>
        <CardHeader
          title="Source-to-Target Attack Vector"
          subtitle="Interactive visual path from adversarial source host through gateway to target cluster"
          icon={<Activity className="w-5 h-5 text-[#007BA7]" />}
        />
        <AttackGraph
          sourceIp={detection.flow?.source_ip}
          targetIp={detection.flow?.destination_ip}
          attackType={detection.attack_type}
          height={280}
        />
      </Card>

      {/* Analyst Feedback Triage Form */}
      <Card>
        <CardHeader
          title="Analyst Verification & Feedback Loop"
          subtitle="Submitting feedback feeds into the continuous model evaluation registry"
          icon={<CheckCircle className="w-5 h-5 text-emerald-400 text-xs" />}
        />

        {feedbackSuccess ? (
          <div className="p-4 bg-emerald-500/15 border border-emerald-500/40 rounded-lg text-emerald-400 font-mono text-xs flex items-center gap-2">
            <CheckCircle className="w-4 h-4" />
            <span>Analyst feedback recorded. Model evaluation dataset updated.</span>
          </div>
        ) : (
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-mono uppercase text-[#94A3B8] mb-1.5">
                Investigation Notes & Remediation Context
              </label>
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                rows={3}
                placeholder="Document observed indicator IOCs, firewall actions taken, or reason for classification adjustment..."
                className="w-full bg-[#0A0A0A] border border-[#1E293B] rounded-lg p-3 text-sm text-[#F8FAFC] font-mono focus:border-[#007BA7] focus:outline-none"
              />
            </div>

            <div className="flex items-center gap-3">
              <Button
                variant="primary"
                size="sm"
                onClick={() => handleFeedback(true)}
                isLoading={isSubmitting}
                leftIcon={<CheckCircle className="w-4 h-4" />}
              >
                Confirm True Positive (Malicious)
              </Button>

              <Button
                variant="danger"
                size="sm"
                onClick={() => handleFeedback(false)}
                isLoading={isSubmitting}
                leftIcon={<XCircle className="w-4 h-4" />}
              >
                Mark False Positive (Benign)
              </Button>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
};
