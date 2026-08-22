import React, { useEffect, useState } from 'react';
import { adminApi } from '../../lib/api/admin';
import { Loader2, Search, X } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function Users() {
  const [users, setUsers] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
    const [searchInput, setSearchInput] = useState('');
    useEffect(() => {
      const handler = setTimeout(() => {
        setSearchTerm(searchInput);
        setPage(0);
      }, 300);
      return () => clearTimeout(handler);
    }, [searchInput]);

  const [roleFilter, setRoleFilter] = useState('all');
  const [planFilter, setPlanFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(0);
  const limit = 50;

  useEffect(() => {
    const fetchUsers = async () => {
      setLoading(true);
      try {
        const data = await adminApi.getUsers(limit, page * limit, searchTerm);
        setUsers(data);
      } catch (err) {
        setError(err.message || 'Failed to load users');
      } finally {
        setLoading(false);
      }
    };
    fetchUsers();
  }, [page, searchTerm]);


  const filteredUsers = users.filter(u => {
    const matchesSearch = searchTerm === '' || (u.email || '').toLowerCase().includes(searchTerm.toLowerCase()) || (u.user_id || '').toLowerCase().includes(searchTerm.toLowerCase());
    const matchesRole = roleFilter === 'all' || (u.role || 'user') === roleFilter;
    const matchesPlan = planFilter === 'all' || (u.plan || 'free') === planFilter;
    const matchesStatus = statusFilter === 'all' || (u.status || 'active') === statusFilter;
    return matchesSearch && matchesRole && matchesPlan && matchesStatus;
  });

  if (loading && users.length === 0) {
    return <div className="flex justify-center p-8"><Loader2 className="w-8 h-8 text-indigo-500 animate-spin" /></div>;
  }

  if (error) {
    return <div className="p-4 bg-red-500/10 border border-red-500/50 rounded text-red-400">{error}</div>;
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Users</h1>
        <div className="flex gap-4 mb-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search by email or User ID..."
              className="w-full bg-slate-900 border border-slate-700 rounded pl-10 pr-10 py-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={(e) => { if(e.key === "Enter") { setSearchTerm(searchInput); setPage(0); } }}
            />
            {searchInput && (
              <button onClick={() => { setSearchInput(''); setSearchTerm(''); setPage(0); }} className="absolute right-3 top-2.5">
                <X className="h-4 w-4 text-slate-400 hover:text-white" />
              </button>
            )}
          </div>
        </div>


      {users.length === 0 && page === 0 ? (
        <div className="p-8 text-center text-slate-400 border border-slate-800 rounded bg-slate-900">
          No users found.
        </div>
      ) : (
        <>
          <div className="overflow-x-auto rounded border border-slate-800 relative">
            {loading && <div className="absolute inset-0 bg-slate-950/50 flex items-center justify-center z-10"><Loader2 className="w-8 h-8 text-indigo-500 animate-spin" /></div>}
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
                {filteredUsers.map(u => {
                  let dateStr = 'Date unavailable';
                  if (u.created_at) {
                    const date = new Date(u.created_at);
                    if (!isNaN(date.getTime())) dateStr = date.toLocaleString();
                  }

                  return (
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
                      <td className="px-4 py-3">{dateStr}</td>
                      <td className="px-4 py-3">
                        <Link to={`/admin/users/${u.user_id}`} className="text-indigo-400 hover:text-indigo-300">
                          View
                        </Link>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          <div className="flex justify-between items-center pt-4">
             <button
               disabled={page === 0 || loading}
               onClick={() => setPage(p => p - 1)}
               className="px-4 py-2 bg-slate-800 rounded disabled:opacity-50"
             >
               Previous
             </button>
             <span className="text-slate-400">Page {page + 1}</span>
             <button
               disabled={users.length < limit || loading}
               onClick={() => setPage(p => p + 1)}
               className="px-4 py-2 bg-slate-800 rounded disabled:opacity-50"
             >
               Next
             </button>
          </div>
        </>
      )}
    </div>
  );
}
