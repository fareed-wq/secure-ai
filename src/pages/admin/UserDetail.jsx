import React, { useEffect, useState } from 'react';
import { adminApi } from '../../lib/api/admin';
import { Loader2, ArrowLeft } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';

export default function UserDetail() {
  const { userId } = useParams();
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const data = await adminApi.getUserDetail(userId);
        setUser(data);
      } catch (err) {
        setError(err.message || 'Failed to load user details');
      } finally {
        setLoading(false);
      }
    };
    fetchUser();
  }, [userId]);

  if (loading) {
    return <div className="flex justify-center p-8"><Loader2 className="w-8 h-8 text-indigo-500 animate-spin" /></div>;
  }

  if (error) {
    return <div className="p-4 bg-red-500/10 border border-red-500/50 rounded text-red-400">{error}</div>;
  }

  if (!user) return <div className="p-4">User not found</div>;

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
            <div className="capitalize">{user.plan || 'free'}</div>
          </div>
          <div>
            <div className="text-sm text-slate-400 mb-1">Status</div>
            <div className="capitalize">{user.account_status || user.status || 'active'}</div>
          </div>
          {user.created_at && (
            <div>
              <div className="text-sm text-slate-400 mb-1">Created</div>
              <div>{new Date(user.created_at).toLocaleString()}</div>
            </div>
          )}
          {user.scan_usage !== undefined && (
            <div>
              <div className="text-sm text-slate-400 mb-1">Scan Usage</div>
              <div>{user.scan_usage}</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
