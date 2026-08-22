import React, { useEffect, useState } from 'react';
import { adminApi } from '../../lib/api/admin';
import { Loader2, ArrowLeft, AlertTriangle } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';

export default function UserDetail() {
  const { userId } = useParams();
  const { user: currentUser } = useAuth();
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [quota, setQuota] = useState(null);
  const [quotaError, setQuotaError] = useState(null);
  const [quotaLoading, setQuotaLoading] = useState(false);
  const [actionError, setActionError] = useState(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [modalConfig, setModalConfig] = useState(null);
  const [reason, setReason] = useState('');

  const fetchUser = async () => {
    setLoading(true);
    try {
      const data = await adminApi.getUserDetail(userId);
      setUser(data);
    } catch (err) {
      setError(err.message || 'Failed to load user');
    } finally {
      setLoading(false);
    }
  };

  const fetchQuota = async () => {
    setQuotaLoading(true);
    setQuotaError(null);
    try {
      const data = await adminApi.getUserQuota(userId);
      setQuota(data);
    } catch (err) {
      setQuotaError(err.message || 'Failed to load quota');
    } finally {
      setQuotaLoading(false);
    }
  };

  useEffect(() => {
    fetchUser();
    fetchQuota();
  }, [userId]);

  const handleAction = async () => {
    if (!modalConfig) return;
    setActionLoading(true);
    setActionError(null);
    try {
      await modalConfig.action(userId, reason);
      await fetchUser();
      await fetchQuota();
      setModalConfig(null);
      setReason('');
    } catch (err) {
      setActionError(err.message || 'Action failed');
    } finally {
      setActionLoading(false);
    }
  };



  if (loading) {
    return <div className="flex justify-center p-8"><Loader2 className="w-8 h-8 text-indigo-500 animate-spin" /></div>;
  }

  if (error) {
    return <div className="p-4 bg-red-500/10 border border-red-500/50 rounded text-red-400">{error}</div>;
  }

  if (!user) return <div className="p-4">User not found</div>;

  const status = user.account_status || user.status || 'active';
  const plan = user.plan || 'free';
  const isSelf = currentUser && currentUser.id === user.user_id;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Link to="/admin/users" className="p-2 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200">
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <h1 className="text-2xl font-bold">User Details</h1>
      </div>
      
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 max-w-2xl">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
          <div>
            <div className="text-sm text-slate-400 mb-1">User ID</div>
            <div className="font-mono text-sm break-all">{user.user_id}</div>
          </div>
          {user.email && (
            <div>
              <div className="text-sm text-slate-400 mb-1">Email</div>
              <div>{user.email}</div>
            </div>
          )}
          <div>
            <div className="text-sm text-slate-400 mb-1">Role</div>
            <div className="capitalize">{user.role || 'user'}</div>
          </div>
          <div>
            <div className="text-sm text-slate-400 mb-1">Plan</div>
            <div className="capitalize">{plan}</div>
          </div>
          <div>
            <div className="text-sm text-slate-400 mb-1">Status</div>
            <div className="capitalize">{status}</div>
          </div>
          {user.created_at && (
            <div>
              <div className="text-sm text-slate-400 mb-1">Created</div>
              <div>{new Date(user.created_at).toLocaleString()}</div>
            </div>
          )}
        </div>
      </div>

      {/* Quota Panel — loads independently, errors are isolated */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 max-w-2xl">
        <h2 className="text-lg font-semibold mb-4">QUOTA</h2>
        {quotaLoading && <div className="flex items-center gap-2 text-slate-400"><Loader2 className="w-4 h-4 animate-spin" /> Loading quota...</div>}
        {quotaError && <div className="p-3 bg-red-500/10 border border-red-500/50 rounded text-red-400 text-sm">{quotaError}</div>}
        {quota && !quotaLoading && (
          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-4 text-sm">
              <div>
                <div className="text-slate-400">Limit</div>
                <div className="font-semibold">{quota.limit}</div>
              </div>
              <div>
                <div className="text-slate-400">Used</div>
                <div className="font-semibold">{quota.used}</div>
              </div>
              <div>
                <div className="text-slate-400">Remaining</div>
                <div className="font-semibold">{quota.remaining}</div>
              </div>
            </div>
            {quota.reset_time && (
              <div className="text-xs text-slate-500">
                Resets: {new Date(quota.reset_time * 1000).toLocaleString()}
              </div>
            )}
            {plan === 'free' && (
              <button
                onClick={() => setModalConfig({
                  title: 'Reset Quota',
                  description: "Reset this user's current Free quota? This resets the current week's Free scan usage to 0.",
                  action: adminApi.resetQuota,
                  confirmText: 'Reset Quota',
                  confirmClass: 'bg-amber-600 hover:bg-amber-700 text-white'
                })}
                disabled={quotaLoading}
                className="mt-2 px-3 py-1.5 bg-amber-600 hover:bg-amber-700 text-white rounded text-sm font-medium transition-colors disabled:opacity-50"
              >
                Reset Current Quota
              </button>
            )}
          </div>
        )}
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 max-w-2xl">
        <h2 className="text-lg font-semibold mb-4">ADMIN ACTIONS</h2>
        <div className="flex flex-wrap gap-4">
          {plan === 'free' && (
            <button
              onClick={() => setModalConfig({
                title: 'Grant Professional',
                description: 'Grant Professional plan to this user?',
                action: adminApi.grantProfessional,
                confirmText: 'Grant Professional',
                confirmClass: 'bg-indigo-600 hover:bg-indigo-700 text-white'
              })}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded text-sm font-medium transition-colors"
            >
              Grant Professional
            </button>
          )}

          {plan === 'professional' && (
            <button
              onClick={() => setModalConfig({
                title: 'Remove Professional',
                description: 'Remove Professional plan and return this user to Free?',
                action: adminApi.removeProfessional,
                confirmText: 'Remove Professional',
                confirmClass: 'bg-orange-600 hover:bg-orange-700 text-white'
              })}
              className="px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded text-sm font-medium transition-colors"
            >
              Remove Professional
            </button>
          )}

          {status === 'active' && !isSelf && (
            <button
              onClick={() => setModalConfig({
                title: 'Suspend User',
                description: 'Suspend this user? They will be blocked from protected account and scan actions.',
                action: adminApi.suspendUser,
                confirmText: 'Suspend User',
                confirmClass: 'bg-red-600 hover:bg-red-700 text-white'
              })}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded text-sm font-medium transition-colors"
            >
              Suspend User
            </button>
          )}

          {status === 'suspended' && (
            <button
              onClick={() => setModalConfig({
                title: 'Reactivate User',
                description: 'Reactivate this user?',
                action: adminApi.reactivateUser,
                confirmText: 'Reactivate',
                confirmClass: 'bg-green-600 hover:bg-green-700 text-white'
              })}
              className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded text-sm font-medium transition-colors"
            >
              Reactivate User
            </button>
          )}
        </div>
      </div>

      {modalConfig && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-md w-full p-6 space-y-4">
            <h3 className="text-xl font-semibold flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-yellow-500" />
              {modalConfig.title}
            </h3>
            <p className="text-slate-300">{modalConfig.description}</p>
            
            {actionError && (
              <div className="p-3 bg-red-500/10 border border-red-500/50 rounded text-red-400 text-sm">
                {actionError}
              </div>
            )}

            <div>
              <label className="block text-sm text-slate-400 mb-1">Reason (optional)</label>
              <textarea
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                maxLength={500}
                className="w-full bg-slate-800 border border-slate-700 rounded p-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                placeholder="Enter reason for this action..."
                rows={3}
              />
            </div>

            <div className="flex justify-end gap-3 pt-4">
              <button
                disabled={actionLoading}
                onClick={() => { setModalConfig(null); setActionError(null); setReason(''); }}
                className="px-4 py-2 text-slate-300 hover:text-white disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                disabled={actionLoading}
                onClick={handleAction}
                className={`px-4 py-2 rounded font-medium disabled:opacity-50 flex items-center gap-2 ${modalConfig.confirmClass}`}
              >
                {actionLoading && <Loader2 className="w-4 h-4 animate-spin" />}
                {modalConfig.confirmText}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
