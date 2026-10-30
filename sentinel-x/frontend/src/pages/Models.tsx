import React, { useEffect, useState } from 'react';
import {
  Layers,
  CheckCircle,
  Clock,
  ShieldCheck,
  Zap,
  RefreshCw,
  FileCode,
  Lock,
} from 'lucide-react';
import { Card, CardHeader } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { useAuth } from '../app/context/AuthContext';
import { api } from '../services/api';
import { ModelVersionItem } from '../types';
import { formatDate } from '../utils/formatters';

export const Models: React.FC = () => {
  const { hasRole } = useAuth();
  const isAdmin = hasRole(['ADMIN']);

  const [models, setModels] = useState<ModelVersionItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [activatingId, setActivatingId] = useState<string | null>(null);

  const loadModels = async () => {
    setIsLoading(true);
    try {
      const data = await api.models.list();
      setModels(data);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadModels();
  }, []);

  const handleActivate = async (modelId: string) => {
    if (!isAdmin) return;
    setActivatingId(modelId);
    try {
      await api.models.activate(modelId);
      // Update local state to mark this model ACTIVE and others RETIRED
      setModels((prev) =>
        prev.map((m) => {
          if (m.id === modelId) return { ...m, status: 'ACTIVE' };
          if (m.algorithm.includes('XGBoost') || m.algorithm.includes('Random')) {
            return { ...m, status: 'RETIRED' };
          }
          return m;
        })
      );
    } finally {
      setActivatingId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#1E293B]">
        <div>
          <h2 className="text-xl font-bold font-mono tracking-tight text-[#F8FAFC] flex items-center gap-2">
            <span>MACHINE LEARNING MODEL REGISTRY</span>
          </h2>
          <p className="text-xs text-[#94A3B8] font-mono mt-0.5">
            Artifact versioning, cryptographic checksum verification, and production model activation
          </p>
        </div>

        <Button
          variant="secondary"
          size="sm"
          onClick={loadModels}
          isLoading={isLoading}
          leftIcon={<RefreshCw className="w-3.5 h-3.5" />}
        >
          Refresh Registry
        </Button>
      </div>

      {/* Model Cards */}
      <div className="grid grid-cols-1 gap-6">
        {models.map((model) => {
          const isActive = model.status === 'ACTIVE';
          return (
            <Card
              key={model.id}
              glow={isActive ? 'cerulean' : 'none'}
              className="p-6"
            >
              <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-3">
                    <h3 className="text-lg font-bold font-mono text-[#F8FAFC]">{model.name}</h3>
                    <Badge
                      severity={isActive ? 'BENIGN' : 'LOW'}
                      variant={isActive ? 'solid' : 'subtle'}
                      showDot={isActive}
                    >
                      {model.status}
                    </Badge>
                  </div>
                  <p className="text-xs font-mono text-[#007BA7] font-semibold">{model.algorithm}</p>
                </div>

                {/* Activation Action Button */}
                <div>
                  {isActive ? (
                    <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#007BA7]/15 border border-[#007BA7]/40 text-[#007BA7] text-xs font-mono font-bold">
                      <ShieldCheck className="w-4 h-4" />
                      <span>SERVING PRODUCTION INFERENCE</span>
                    </div>
                  ) : (
                    <Button
                      variant="primary"
                      size="sm"
                      disabled={!isAdmin}
                      isLoading={activatingId === model.id}
                      onClick={() => handleActivate(model.id)}
                      leftIcon={<Zap className="w-3.5 h-3.5" />}
                    >
                      {isAdmin ? 'Promote to Active' : 'Admin Required to Promote'}
                    </Button>
                  )}
                </div>
              </div>

              {/* Evaluation Metrics */}
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mt-5 pt-4 border-t border-[#1E293B]">
                <div className="p-2.5 bg-[#0A0A0A] border border-[#1E293B] rounded-lg text-center font-mono">
                  <span className="text-[10px] text-[#94A3B8] uppercase">Accuracy</span>
                  <p className="text-base font-bold text-white mt-0.5">
                    {model.metrics.accuracy ? `${(model.metrics.accuracy * 100).toFixed(1)}%` : 'N/A'}
                  </p>
                </div>

                <div className="p-2.5 bg-[#0A0A0A] border border-[#1E293B] rounded-lg text-center font-mono">
                  <span className="text-[10px] text-[#94A3B8] uppercase">Precision</span>
                  <p className="text-base font-bold text-white mt-0.5">
                    {model.metrics.precision ? `${(model.metrics.precision * 100).toFixed(1)}%` : 'N/A'}
                  </p>
                </div>

                <div className="p-2.5 bg-[#0A0A0A] border border-[#1E293B] rounded-lg text-center font-mono">
                  <span className="text-[10px] text-[#94A3B8] uppercase">Recall</span>
                  <p className="text-base font-bold text-white mt-0.5">
                    {model.metrics.recall ? `${(model.metrics.recall * 100).toFixed(1)}%` : 'N/A'}
                  </p>
                </div>

                <div className="p-2.5 bg-[#0A0A0A] border border-[#1E293B] rounded-lg text-center font-mono">
                  <span className="text-[10px] text-[#94A3B8] uppercase">F1-Score</span>
                  <p className="text-base font-bold text-[#007BA7] mt-0.5">
                    {model.metrics.f1_score ? `${(model.metrics.f1_score * 100).toFixed(1)}%` : 'N/A'}
                  </p>
                </div>

                <div className="p-2.5 bg-[#0A0A0A] border border-[#1E293B] rounded-lg text-center font-mono">
                  <span className="text-[10px] text-[#94A3B8] uppercase">ROC-AUC</span>
                  <p className="text-base font-bold text-white mt-0.5">
                    {model.metrics.roc_auc ? `${(model.metrics.roc_auc * 100).toFixed(1)}%` : 'N/A'}
                  </p>
                </div>
              </div>

              {/* Artifact Metadata Details */}
              <div className="mt-4 pt-3 border-t border-[#1E293B]/40 grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono text-[#94A3B8]">
                <div>
                  <span className="text-[10px] uppercase text-[#94A3B8] block">Artifact Storage URI</span>
                  <span className="text-white truncate block mt-0.5">{model.artifact_uri}</span>
                </div>

                <div>
                  <span className="text-[10px] uppercase text-[#94A3B8] block">SHA-256 Checksum</span>
                  <span className="text-gray-400 truncate block mt-0.5 font-mono text-[11px]">
                    {model.checksum}
                  </span>
                </div>

                <div>
                  <span className="text-[10px] uppercase text-[#94A3B8] block">Trained Timestamp</span>
                  <span className="text-white block mt-0.5">{formatDate(model.trained_at)}</span>
                </div>
              </div>
            </Card>
          );
        })}
      </div>
    </div>
  );
};
