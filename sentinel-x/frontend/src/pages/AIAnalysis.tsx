import React, { useState } from 'react';
import {
  Cpu,
  Layers,
  Sparkles,
  Play,
  CheckCircle,
  AlertTriangle,
  Activity,
  Sliders,
} from 'lucide-react';
import { Card, CardHeader } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Input } from '../components/ui/Input';
import { ShapBarChart } from '../components/charts/ShapBarChart';

export const AIAnalysis: React.FC = () => {
  // Sandbox form state
  const [packetRate, setPacketRate] = useState('14500');
  const [synFlags, setSynFlags] = useState('280');
  const [durationMs, setDurationMs] = useState('120');
  const [destPort, setDestPort] = useState('80');
  const [isInferring, setIsInferring] = useState(false);
  const [sandboxResult, setSandboxResult] = useState<{
    prediction: string;
    confidence: number;
    anomalyScore: number;
    riskScore: number;
    severity: string;
    shapFeatures: Array<{ feature: string; impact: number }>;
  } | null>({
    prediction: 'DDoS (SYN-Flood)',
    confidence: 0.988,
    anomalyScore: 0.914,
    riskScore: 96.2,
    severity: 'CRITICAL',
    shapFeatures: [
      { feature: 'syn_flag_count', impact: 0.44 },
      { feature: 'packet_rate_per_sec', impact: 0.32 },
      { feature: 'flow_duration_ms', impact: 0.14 },
      { feature: 'destination_port_entropy', impact: 0.08 },
      { feature: 'fwd_packet_length_mean', impact: -0.16 },
    ],
  });

  const handleTestInference = (e: React.FormEvent) => {
    e.preventDefault();
    setIsInferring(true);

    setTimeout(() => {
      const synVal = parseInt(synFlags) || 0;
      const rateVal = parseInt(packetRate) || 0;

      let pred = 'Benign';
      let conf = 0.96;
      let anomaly = 0.08;
      let risk = 12.0;
      let sev = 'BENIGN';

      if (synVal > 100 || rateVal > 10000) {
        pred = 'DDoS (SYN-Flood)';
        conf = 0.985;
        anomaly = 0.912;
        risk = 95.8;
        sev = 'CRITICAL';
      } else if (destPort === '22') {
        pred = 'BruteForce (SSH)';
        conf = 0.94;
        anomaly = 0.81;
        risk = 86.4;
        sev = 'HIGH';
      }

      setSandboxResult({
        prediction: pred,
        confidence: conf,
        anomalyScore: anomaly,
        riskScore: risk,
        severity: sev,
        shapFeatures: [
          { feature: 'syn_flag_count', impact: synVal > 100 ? 0.42 : -0.22 },
          { feature: 'packet_rate_per_sec', impact: rateVal > 10000 ? 0.35 : -0.18 },
          { feature: 'flow_duration_ms', impact: 0.12 },
          { feature: 'destination_port_entropy', impact: destPort === '22' ? 0.28 : 0.05 },
          { feature: 'fwd_packet_length_mean', impact: -0.14 },
        ],
      });
      setIsInferring(false);
    }, 450);
  };

  const globalShapFeatures = [
    { feature: 'syn_flag_count', impact: 0.48 },
    { feature: 'packet_rate_per_sec', impact: 0.39 },
    { feature: 'destination_port_entropy', impact: 0.31 },
    { feature: 'flow_iat_std', impact: 0.26 },
    { feature: 'failed_handshake_ratio', impact: 0.22 },
    { feature: 'fwd_packet_length_mean', impact: -0.19 },
    { feature: 'flow_duration_ms', impact: 0.15 },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="pb-2 border-b border-[#1E293B]">
        <h2 className="text-xl font-bold font-mono tracking-tight text-[#F8FAFC] flex items-center gap-2">
          <span>AI EXPLAINABILITY & MODEL DIAGNOSTICS (XAI)</span>
        </h2>
        <p className="text-xs text-[#94A3B8] font-mono mt-0.5">
          Feature contribution analysis via TreeSHAP, supervised inference diagnostics, and live sandbox
        </p>
      </div>

      {/* Model Engine Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Supervised Classifier */}
        <Card glow="cerulean">
          <CardHeader
            title="Supervised Attack Classifier"
            subtitle="Extreme Gradient Boosting (XGBoost) Multi-Class Engine"
            icon={<Cpu className="w-5 h-5 text-[#007BA7]" />}
          />
          <div className="space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between p-2.5 bg-[#0A0A0A] border border-[#1E293B] rounded-lg">
              <span className="text-[#94A3B8]">Active Artifact:</span>
              <span className="text-white font-bold">sentinel_xgb_v1.joblib</span>
            </div>
            <div className="grid grid-cols-3 gap-2 text-center">
              <div className="p-2 bg-[#0A0A0A] border border-[#1E293B] rounded">
                <span className="text-[10px] text-[#94A3B8]">ACCURACY</span>
                <p className="text-sm font-bold text-[#007BA7]">99.4%</p>
              </div>
              <div className="p-2 bg-[#0A0A0A] border border-[#1E293B] rounded">
                <span className="text-[10px] text-[#94A3B8]">PRECISION</span>
                <p className="text-sm font-bold text-white">98.8%</p>
              </div>
              <div className="p-2 bg-[#0A0A0A] border border-[#1E293B] rounded">
                <span className="text-[10px] text-[#94A3B8]">F1-SCORE</span>
                <p className="text-sm font-bold text-white">98.9%</p>
              </div>
            </div>
          </div>
        </Card>

        {/* Unsupervised Anomaly Detector */}
        <Card glow="rose">
          <CardHeader
            title="Unsupervised Anomaly Detector"
            subtitle="Isolation Forest Outlier Detection Engine (Zero-Day Discovery)"
            icon={<Activity className="w-5 h-5 text-[#FF2D95]" />}
          />
          <div className="space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between p-2.5 bg-[#0A0A0A] border border-[#1E293B] rounded-lg">
              <span className="text-[#94A3B8]">Active Artifact:</span>
              <span className="text-white font-bold">sentinel_if_v1.joblib</span>
            </div>
            <div className="grid grid-cols-3 gap-2 text-center">
              <div className="p-2 bg-[#0A0A0A] border border-[#1E293B] rounded">
                <span className="text-[10px] text-[#94A3B8]">CONTAMINATION</span>
                <p className="text-sm font-bold text-[#FF2D95]">0.035</p>
              </div>
              <div className="p-2 bg-[#0A0A0A] border border-[#1E293B] rounded">
                <span className="text-[10px] text-[#94A3B8]">TREES</span>
                <p className="text-sm font-bold text-white">200</p>
              </div>
              <div className="p-2 bg-[#0A0A0A] border border-[#1E293B] rounded">
                <span className="text-[10px] text-[#94A3B8]">AUC-ROC</span>
                <p className="text-sm font-bold text-white">98.1%</p>
              </div>
            </div>
          </div>
        </Card>
      </div>

      {/* Global SHAP Feature Importance */}
      <Card>
        <CardHeader
          title="Global SHAP Feature Importance (Ensemble Level)"
          subtitle="Top telemetry metrics driving model decisions across all historical detections (#FF2D95 Malicious vs #007BA7 Benign)"
          icon={<Layers className="w-5 h-5 text-[#007BA7]" />}
        />
        <ShapBarChart features={globalShapFeatures} height={280} />
      </Card>

      {/* Flow Inference Sandbox */}
      <Card>
        <CardHeader
          title="Live Flow Inference Sandbox"
          subtitle="Input synthetic or captured packet telemetry to simulate production inference and inspect SHAP outputs"
          icon={<Sliders className="w-5 h-5 text-[#007BA7]" />}
        />

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Input Form */}
          <form onSubmit={handleTestInference} className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <Input
                label="Packets Per Second"
                value={packetRate}
                onChange={(e) => setPacketRate(e.target.value)}
              />
              <Input
                label="SYN Flag Count"
                value={synFlags}
                onChange={(e) => setSynFlags(e.target.value)}
              />
              <Input
                label="Flow Duration (ms)"
                value={durationMs}
                onChange={(e) => setDurationMs(e.target.value)}
              />
              <Input
                label="Destination Port"
                value={destPort}
                onChange={(e) => setDestPort(e.target.value)}
              />
            </div>

            <Button
              type="submit"
              variant="primary"
              size="md"
              isLoading={isInferring}
              leftIcon={<Play className="w-4 h-4" />}
            >
              Execute Model Inference
            </Button>
          </form>

          {/* Sandbox Prediction Output */}
          {sandboxResult && (
            <div className="p-4 bg-[#0A0A0A] border border-[#1E293B] rounded-xl flex flex-col justify-between font-mono text-xs">
              <div>
                <div className="flex items-center justify-between pb-3 border-b border-[#1E293B]">
                  <span className="text-[#94A3B8] uppercase text-[10px]">Predicted Classification</span>
                  <Badge severity={sandboxResult.severity} showDot>
                    {sandboxResult.severity}
                  </Badge>
                </div>

                <div className="grid grid-cols-2 gap-3 my-3">
                  <div>
                    <span className="text-[#94A3B8] text-[10px]">CLASSIFIER CLASS</span>
                    <p className="text-white font-bold text-sm">{sandboxResult.prediction}</p>
                  </div>
                  <div>
                    <span className="text-[#94A3B8] text-[10px]">CONFIDENCE</span>
                    <p className="text-[#007BA7] font-bold text-sm">
                      {(sandboxResult.confidence * 100).toFixed(1)}%
                    </p>
                  </div>
                  <div>
                    <span className="text-[#94A3B8] text-[10px]">ANOMALY SCORE</span>
                    <p className="text-white font-bold text-sm">{sandboxResult.anomalyScore}</p>
                  </div>
                  <div>
                    <span className="text-[#94A3B8] text-[10px]">DETERMINISTIC RISK</span>
                    <p className="text-[#FF2D95] font-extrabold text-sm">{sandboxResult.riskScore}/100</p>
                  </div>
                </div>

                <div className="mt-2">
                  <span className="text-[10px] text-[#94A3B8] uppercase block mb-1">
                    Instant SHAP Breakdown
                  </span>
                  <ShapBarChart features={sandboxResult.shapFeatures} height={140} />
                </div>
              </div>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
};
