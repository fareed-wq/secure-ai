import React, { useEffect, useState } from 'react';
import { adminApi } from '../../lib/api/admin';
import { Loader2 } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function Users() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const data = await adminApi.getUsers(50, 0);
        setUsers(data);
      } catch (err) {
        setError(err.message || 'Failed to load users');
      } finally {
        setLoading(false);
      }
    };
    fetchUsers();
  }, []);

  if (loading) {
    return <div className="flex justify-center p-8"><Loader2 className="w-8 h-8 text-indigo-500 animate-spin" /></div>;
  }

  if (error) {
    return <div className="p-4 bg-red-500/10 border border-red-500/50 rounded text-red-400">{error}</div>;
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Users</h1>
      
      {users.length === 0 ? (
        <div className="p-8 text-center text-slate-400 border border-slate-800 rounded bg-slate-900">
          No users found.
        </div>
      ) : (
        <div className="overflow-x-auto rounded border border-slate-800">
          <table className="w-full text-left text-sm whitespace-nowrap">
            <thead className="bg-slate-900 border-b border-slate-800 text-slate-400">
              <tr>
                <th className="px-4 py-3 font-medium">EMAIL</th>
                <th className="px-4 py-3 font-medium">ROLE</th>
                <th className="px-4 py-3 font-medium">PLAN</th>
                <th className="px-4 py-3 font-medium">STATUS</th>
                <th className="px-4 py-3 font-medium">CREATED</th>
                <th className="px-4 py-3 font-medium">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {users.map(u => (
                <tr key={u.user_id} className="hover:bg-slate-800/50">
                  <td className="px-4 py-3">{u.email || 'Unknown'}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs ${u.role === 'admin' ? 'bg-indigo-500/20 text-indigo-300' : 'bg-slate-700 text-slate-300'}`}>
                      {u.role || 'user'}
                    </span>
                  </td>
                  <td className="px-4 py-3 capitalize">{u.plan || 'free'}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs ${u.status === 'suspended' ? 'bg-red-500/20 text-red-300' : 'bg-green-500/20 text-green-300'}`}>
                      {u.status || 'active'}
                    </span>
                  </td>
                  <td className="px-4 py-3">{new Date(u.created_at).toLocaleString()}</td>
                  <td className="px-4 py-3">
                    <Link to={`/admin/users/${u.user_id}`} className="text-indigo-400 hover:text-indigo-300">
                      View
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
