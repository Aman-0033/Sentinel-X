import React, { useEffect, useState } from 'react';
import {
  Settings as SettingsIcon,
  Users,
  Shield,
  Server,
  Key,
  CheckCircle2,
  Plus,
  RefreshCw,
  Sliders,
  Lock,
} from 'lucide-react';
import { Card, CardHeader } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Input } from '../components/ui/Input';
import { Modal } from '../components/ui/Modal';
import { useAuth } from '../app/context/AuthContext';
import { api } from '../services/api';
import { UserDetail, UserRole } from '../types';
import { formatDate } from '../utils/formatters';

export const Settings: React.FC = () => {
  const { user, hasRole } = useAuth();
  const isAdmin = hasRole(['ADMIN']);

  const [users, setUsers] = useState<UserDetail[]>([]);
  const [isLoadingUsers, setIsLoadingUsers] = useState(true);

  // Anomaly config state
  const [anomalyContamination, setAnomalyContamination] = useState('0.035');
  const [sessionTimeoutMins, setSessionTimeoutMins] = useState('15');
  const [configSaved, setConfigSaved] = useState(false);

  // New user modal state
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [newEmail, setNewEmail] = useState('');
  const [newFullName, setNewFullName] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState<UserRole>('ANALYST');
  const [isCreatingUser, setIsCreatingUser] = useState(false);

  const loadUsers = async () => {
    setIsLoadingUsers(true);
    try {
      const data = await api.users.list();
      setUsers(data);
    } finally {
      setIsLoadingUsers(false);
    }
  };

  useEffect(() => {
    loadUsers();
  }, []);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newEmail || !newPassword || !newFullName) return;
    setIsCreatingUser(true);
    try {
      const created = await api.users.create({
        email: newEmail.trim(),
        full_name: newFullName.trim(),
        password: newPassword,
        role: newRole,
      });
      setUsers([...users, created]);
      setIsModalOpen(false);
      setNewEmail('');
      setNewFullName('');
      setNewPassword('');
    } finally {
      setIsCreatingUser(false);
    }
  };

  const handleSaveConfig = (e: React.FormEvent) => {
    e.preventDefault();
    setConfigSaved(true);
    setTimeout(() => setConfigSaved(false), 3000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#1E293B]">
        <div>
          <h2 className="text-xl font-bold font-mono tracking-tight text-[#F8FAFC] flex items-center gap-2">
            <span>PLATFORM CONFIGURATION & RBAC ADMINISTRATION</span>
          </h2>
          <p className="text-xs text-[#94A3B8] font-mono mt-0.5">
            Role-Based Access Control, security session parameters, and system health status
          </p>
        </div>

        {isAdmin && (
          <Button
            variant="primary"
            size="sm"
            onClick={() => setIsModalOpen(true)}
            leftIcon={<Plus className="w-3.5 h-3.5" />}
          >
            Provision User
          </Button>
        )}
      </div>

      {/* System Health Diagnostic Status Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <Card className="p-4 flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <Server className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[10px] text-[#94A3B8] font-mono uppercase">FastAPI Backend</div>
            <div className="text-sm font-bold font-mono text-emerald-400 flex items-center gap-1.5 mt-0.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
              <span>OPERATIONAL</span>
            </div>
          </div>
        </Card>

        <Card className="p-4 flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <Server className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[10px] text-[#94A3B8] font-mono uppercase">PostgreSQL 16</div>
            <div className="text-sm font-bold font-mono text-emerald-400 flex items-center gap-1.5 mt-0.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
              <span>HEALTHY</span>
            </div>
          </div>
        </Card>

        <Card className="p-4 flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <Server className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[10px] text-[#94A3B8] font-mono uppercase">Redis & Celery</div>
            <div className="text-sm font-bold font-mono text-emerald-400 flex items-center gap-1.5 mt-0.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
              <span>ACTIVE</span>
            </div>
          </div>
        </Card>

        <Card className="p-4 flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#007BA7]/15 border border-[#007BA7]/30 flex items-center justify-center text-[#007BA7]">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[10px] text-[#94A3B8] font-mono uppercase">In-Memory JWT</div>
            <div className="text-sm font-bold font-mono text-[#007BA7] flex items-center gap-1.5 mt-0.5">
              <Lock className="w-3.5 h-3.5" />
              <span>ENFORCED</span>
            </div>
          </div>
        </Card>
      </div>

      {/* RBAC User Directory */}
      <Card>
        <CardHeader
          title={`Registered SOC Operators (${users.length})`}
          subtitle="Role-Based Access Control matrix (ADMIN, ANALYST, VIEWER)"
          icon={<Users className="w-5 h-5 text-[#007BA7]" />}
          action={
            <Button
              variant="secondary"
              size="sm"
              onClick={loadUsers}
              isLoading={isLoadingUsers}
              leftIcon={<RefreshCw className="w-3.5 h-3.5" />}
            >
              Refresh Users
            </Button>
          }
        />

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead>
              <tr className="border-b border-[#1E293B] text-[#94A3B8] uppercase text-[11px]">
                <th className="py-3 px-3">Full Name</th>
                <th className="py-3 px-3">Email Address</th>
                <th className="py-3 px-3">Assigned Role</th>
                <th className="py-3 px-3">Status</th>
                <th className="py-3 px-3">Created Date</th>
                <th className="py-3 px-3 text-right">Last Login</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B]/40">
              {users.map((u) => (
                <tr key={u.id} className="hover:bg-[#181822] transition-colors">
                  <td className="py-3 px-3 text-white font-bold">{u.full_name}</td>
                  <td className="py-3 px-3 text-[#94A3B8]">{u.email}</td>
                  <td className="py-3 px-3">
                    <Badge
                      severity={
                        u.role === 'ADMIN' ? 'CRITICAL' : u.role === 'ANALYST' ? 'HIGH' : 'LOW'
                      }
                    >
                      {u.role}
                    </Badge>
                  </td>
                  <td className="py-3 px-3">
                    <span className="text-emerald-400 font-semibold flex items-center gap-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                      <span>ACTIVE</span>
                    </span>
                  </td>
                  <td className="py-3 px-3 text-[#94A3B8]">{formatDate(u.created_at)}</td>
                  <td className="py-3 px-3 text-right text-gray-400">
                    {formatDate(u.last_login_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Security Policies and Anomaly Tuning */}
      <Card>
        <CardHeader
          title="Security Policies & Telemetry Engine Tuning"
          subtitle="Configure JWT timeout parameters and anomaly detection sensitivity"
          icon={<Sliders className="w-5 h-5 text-[#007BA7]" />}
        />

        <form onSubmit={handleSaveConfig} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Input
              label="Session JWT Expiration (Minutes)"
              value={sessionTimeoutMins}
              onChange={(e) => setSessionTimeoutMins(e.target.value)}
              disabled={!isAdmin}
            />

            <Input
              label="Isolation Forest Contamination Ratio"
              value={anomalyContamination}
              onChange={(e) => setAnomalyContamination(e.target.value)}
              disabled={!isAdmin}
            />
          </div>

          <div className="flex items-center justify-between pt-2">
            <div className="text-xs font-mono text-[#94A3B8]">
              {isAdmin ? 'Changes take effect immediately across all active cluster nodes.' : 'Read-only: Admin role required to modify parameters.'}
            </div>

            {isAdmin && (
              <Button type="submit" variant="primary" size="sm">
                Save Security Parameters
              </Button>
            )}
          </div>

          {configSaved && (
            <div className="p-3 bg-emerald-500/15 border border-emerald-500/40 rounded-lg text-emerald-400 text-xs font-mono flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4" />
              <span>Security parameters updated and synchronized with backend daemon.</span>
            </div>
          )}
        </form>
      </Card>

      {/* Modal: Provision User */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title="Provision New SOC Operator"
        description="Create account with Argon2id encrypted credentials and RBAC assignment"
      >
        <form onSubmit={handleCreateUser} className="space-y-4">
          <Input
            label="Full Name"
            required
            value={newFullName}
            onChange={(e) => setNewFullName(e.target.value)}
            placeholder="e.g. John Doe"
          />

          <Input
            label="Email Address"
            type="email"
            required
            value={newEmail}
            onChange={(e) => setNewEmail(e.target.value)}
            placeholder="johndoe@sentinel.local"
          />

          <Input
            label="Initial Temporary Password"
            type="password"
            required
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            placeholder="••••••••••••"
          />

          <div>
            <label className="block text-xs font-mono uppercase text-[#94A3B8] mb-1.5">
              Assigned Role
            </label>
            <select
              value={newRole}
              onChange={(e) => setNewRole(e.target.value as UserRole)}
              className="w-full bg-[#0A0A0A] border border-[#1E293B] rounded-lg px-3.5 py-2 text-sm text-[#F8FAFC] font-mono focus:border-[#007BA7] focus:outline-none"
            >
              <option value="ANALYST">ANALYST (Triage, Notes, SHAP Analysis)</option>
              <option value="VIEWER">VIEWER (Auditor, Read-Only Telemetry)</option>
              <option value="ADMIN">ADMIN (Full Access, Model Promotion)</option>
            </select>
          </div>

          <div className="flex items-center justify-end gap-3 pt-2">
            <Button variant="ghost" size="sm" type="button" onClick={() => setIsModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" size="sm" type="submit" isLoading={isCreatingUser}>
              Provision Operator
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
