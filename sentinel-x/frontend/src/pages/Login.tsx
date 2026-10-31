import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../app/context/AuthContext';
import { Shield, Lock, Mail, AlertCircle, ArrowRight, CheckCircle2 } from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';

export const Login: React.FC = () => {
  const navigate = useNavigate();
  const { login } = useAuth();

  const [email, setEmail] = useState('admin@sentinel.internal');
  const [password, setPassword] = useState('SentinelAdmin2026!');
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      await login(email, password);
      navigate('/dashboard');
    } catch (err: any) {
      setError(err.message || 'Invalid authentication credentials.');
    } finally {
      setIsLoading(false);
    }
  };

  const fillCredentials = (roleEmail: string, rolePassword: string) => {
    setEmail(roleEmail);
    setPassword(rolePassword);
    setError(null);
  };

  return (
    <div className="min-h-screen bg-[#0A0A0A] flex flex-col items-center justify-center p-4 cyber-grid relative selection:bg-[#007BA7] selection:text-white">
      {/* Background ambient lighting */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-96 h-96 bg-[#007BA7]/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/3 w-64 h-64 bg-[#FF2D95]/5 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md bg-[#121216] border border-[#1E293B] rounded-2xl shadow-2xl p-8 relative z-10">
        {/* Header with Shield Icon */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-[#007BA7]/15 border border-[#007BA7]/40 text-[#007BA7] shadow-glow-cerulean mb-4">
            <Shield className="w-8 h-8 text-[#007BA7]" />
          </div>
          <h1 className="text-2xl font-bold font-mono tracking-tight text-[#F8FAFC]">
            SENTINEL-X
          </h1>
          <p className="text-xs text-[#94A3B8] font-mono mt-1">
            AI-POWERED INTRUSION DETECTION & SOC
          </p>
        </div>

        {error && (
          <div className="mb-6 p-3.5 bg-[#FF2D95]/15 border border-[#FF2D95]/40 rounded-lg flex items-start gap-2.5 text-[#FF2D95] text-xs font-mono shadow-glow-rose">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <Input
            label="Analyst Email"
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="analyst@sentinel.local"
            leftIcon={<Mail className="w-4 h-4" />}
          />

          <Input
            label="Secure Password"
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••••••"
            leftIcon={<Lock className="w-4 h-4" />}
          />

          <Button
            type="submit"
            variant="primary"
            size="lg"
            className="w-full mt-2"
            isLoading={isLoading}
            rightIcon={<ArrowRight className="w-4 h-4" />}
          >
            Authenticate to SOC
          </Button>
        </form>

        {/* Quick Demo Role Selector */}
        <div className="mt-8 pt-6 border-t border-[#1E293B]">
          <p className="text-[11px] font-mono uppercase tracking-wider text-[#94A3B8] text-center mb-3">
            Quick-Fill Role Credentials
          </p>
          <div className="grid grid-cols-3 gap-2">
            <button
              type="button"
              onClick={() => fillCredentials('admin@sentinel.internal', 'SentinelAdmin2026!')}
              className="px-2.5 py-1.5 bg-[#0A0A0A] hover:bg-[#181822] border border-[#1E293B] hover:border-[#007BA7] rounded text-xs font-mono text-[#F8FAFC] transition-colors flex flex-col items-center"
            >
              <span className="font-semibold text-[#007BA7]">ADMIN</span>
              <span className="text-[9px] text-[#94A3B8]">Full Access</span>
            </button>

            <button
              type="button"
              onClick={() => fillCredentials('analyst@sentinel.internal', 'SentinelAnalyst2026!')}
              className="px-2.5 py-1.5 bg-[#0A0A0A] hover:bg-[#181822] border border-[#1E293B] hover:border-[#FF2D95] rounded text-xs font-mono text-[#F8FAFC] transition-colors flex flex-col items-center"
            >
              <span className="font-semibold text-[#FF2D95]">ANALYST</span>
              <span className="text-[9px] text-[#94A3B8]">Triage & XAI</span>
            </button>

            <button
              type="button"
              onClick={() => fillCredentials('viewer@sentinel.internal', 'SentinelViewer2026!')}
              className="px-2.5 py-1.5 bg-[#0A0A0A] hover:bg-[#181822] border border-[#1E293B] hover:border-emerald-500 rounded text-xs font-mono text-[#F8FAFC] transition-colors flex flex-col items-center"
            >
              <span className="font-semibold text-emerald-400">VIEWER</span>
              <span className="text-[9px] text-[#94A3B8]">Read Only</span>
            </button>
          </div>
        </div>

        {/* Security Disclaimers */}
        <div className="mt-6 flex items-center justify-center gap-1.5 text-[10px] text-[#94A3B8] font-mono">
          <CheckCircle2 className="w-3.5 h-3.5 text-[#007BA7]" />
          <span>In-Memory JWT & Argon2id Encrypted Channel</span>
        </div>
      </div>
    </div>
  );
};
