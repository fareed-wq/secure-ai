import React, { useEffect, useState } from 'react';
import { adminApi } from '../../lib/api/admin';
import { Loader2, Search, X } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export default function Scans() {
  const [scans, setScans] = useState([]);
  const [searchTermUrl, setSearchTermUrl] = useState('');
  const [searchTermUser, setSearchTermUser] = useState('');
  const [scanTypeFilter, setScanTypeFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(0);
  const [searchTerm, setSearchTerm] = useState('');
    const [searchInput, setSearchInput] = useState('');
    useEffect(() => {
      const handler = setTimeout(() => {
        setSearchTerm(searchInput);
        setPage(0);
      }, 300);
      return () => clearTimeout(handler);
    }, [searchInput]);

  const limit = 50;

  useEffect(() => {
    const fetchScans = async () => {
      setLoading(true);
      try {
        const data = await adminApi.getScans(limit, page * limit, searchTerm);
        setScans(Array.isArray(data) ? data : []);
      } catch (err) {
        setError(err.message || 'Failed to load scans');
      } finally {
        setLoading(false);
      }
    };
    fetchScans();
  }, [page, searchTerm]);

  const getScanModeLabel = (mode, rawMode) => {
    if (mode === 'Advanced' || mode === 'Basic') return mode;
    if (rawMode === 'active') return 'Advanced';
    if (rawMode === 'passive' || rawMode === 'basic') return 'Basic';
    return 'Unknown';
  };

  const filteredScans = scans.filter(s => {
    const matchesUrl = searchTermUrl === '' || (s.target_url || s.url || '').toLowerCase().includes(searchTermUrl.toLowerCase());
    const matchesUser = searchTermUser === '' || (s.user_id || '').toLowerCase().includes(searchTermUser.toLowerCase());
    const sType = getScanModeLabel(s.scan_mode, s.report_data?.scan_mode);
    const matchesType = scanTypeFilter === 'all' || sType.toLowerCase() === scanTypeFilter.toLowerCase();
    return matchesUrl && matchesUser && matchesType;
  });

  if (loading && scans.length === 0) {
    return <div className="flex justify-center p-8"><Loader2 className="w-8 h-8 text-indigo-500 animate-spin" /></div>;
  }

  if (error) {
    return <div className="p-4 bg-red-500/10 border border-red-500/50 rounded text-red-400">{error}</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">Scans</h1>
        <div className="flex gap-4 mb-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search by User ID or target..."
              className="w-full bg-slate-900 border border-slate-700 rounded pl-10 pr-10 py-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={(e) => { if(e.key === 'Enter') { setSearchTerm(searchInput); setPage(0); } }}
            />
            {searchInput && (
              <button onClick={() => { setSearchInput(''); setSearchTerm(''); setPage(0); }} className="absolute right-3 top-2.5">
                <X className="h-4 w-4 text-slate-400 hover:text-white" />
              </button>
            )}
          </div>
        </div>

      </div>

      {scans.length === 0 && page === 0 ? (
        <div className="p-8 text-center text-slate-400 border border-slate-800 rounded bg-slate-900">
          No scans found.
        </div>
      ) : (
        <>
          <div className="overflow-x-auto rounded border border-slate-800 relative bg-slate-950">
            {loading && <div className="absolute inset-0 bg-slate-950/50 flex items-center justify-center z-10"><Loader2 className="w-8 h-8 text-indigo-500 animate-spin" /></div>}
            <table className="w-full text-left text-sm whitespace-nowrap">
              <thead className="bg-slate-900 border-b border-slate-800 text-slate-400">
                <tr>

                  <th className="px-4 py-3 font-medium">TARGET</th>
                  <th className="px-4 py-3 font-medium">USER</th>
                  <th className="px-4 py-3 font-medium">SCAN TYPE</th>
                  <th className="px-4 py-3 font-medium">SCORE</th>
                  <th className="px-4 py-3 font-medium">STATUS</th>
                  <th className="px-4 py-3 font-medium">DATE</th>
                  <th className="px-4 py-3 font-medium">TIME</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {filteredScans.map(scan => {
                  let dateStr = 'Date unavailable';
                  let timeStr = '';
                  if (scan.created_at) {
                    const date = new Date(scan.created_at);
                    if (!isNaN(date.getTime())) {
                       dateStr = date.toLocaleDateString();
                       timeStr = date.toLocaleTimeString();
                    }
                  }

                  return (
                    <tr key={scan.id} className="hover:bg-slate-800/50 transition-colors">

                      <td className="px-4 py-3 truncate max-w-[200px]" title={scan.url || scan.target_url}>{scan.url || scan.target_url}</td>
                      <td className="px-4 py-3 font-mono text-xs truncate max-w-[150px]" title={scan.user_id}>{scan.user_id}</td>
                      <td className="px-4 py-3">{getScanModeLabel(scan.scan_mode, scan.report_data?.scan_mode)}</td>
                      <td className="px-4 py-3">{scan.score !== undefined && scan.score !== null ? scan.score : '-'}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-xs ${scan.status === 'completed' ? 'bg-green-500/20 text-green-300' : scan.status === 'failed' ? 'bg-red-500/20 text-red-300' : 'bg-blue-500/20 text-blue-300'}`}>
                          {scan.status || 'unknown'}
                        </span>
                      </td>
                      <td className="px-4 py-3">{dateStr}</td>
                      <td className="px-4 py-3 text-slate-400">{timeStr}</td>
                    </tr>
                  );
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
               disabled={scans.length < limit || loading}
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
