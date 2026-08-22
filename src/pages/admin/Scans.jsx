import React, { useEffect, useState } from 'react';
import { adminApi } from '../../lib/api/admin';
import { Loader2 } from 'lucide-react';

export default function Scans() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchScans = async () => {
      try {
        const data = await adminApi.getScans(50, 0);
        setScans(Array.isArray(data) ? data : []);
      } catch (err) {
        setError(err.message || 'Failed to load scans');
      } finally {
        setLoading(false);
      }
    };
    fetchScans();
  }, []);

  if (loading) {
    return <div className="flex justify-center p-8"><Loader2 className="w-8 h-8 text-indigo-500 animate-spin" /></div>;
  }

  if (error) {
    return <div className="p-4 bg-red-500/10 border border-red-500/50 rounded text-red-400">{error}</div>;
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Scans</h1>
      
      {scans.length === 0 ? (
        <div className="p-8 text-center text-slate-400 border border-slate-800 rounded bg-slate-900">
          No scans found.
        </div>
      ) : (
        <div className="overflow-x-auto rounded border border-slate-800">
          <table className="w-full text-left text-sm whitespace-nowrap">
            <thead className="bg-slate-900 border-b border-slate-800 text-slate-400">
              <tr>
                <th className="px-4 py-3 font-medium">TARGET</th>
                <th className="px-4 py-3 font-medium">USER</th>
                <th className="px-4 py-3 font-medium">MODE</th>
                <th className="px-4 py-3 font-medium">SCORE</th>
                <th className="px-4 py-3 font-medium">STATUS</th>
                <th className="px-4 py-3 font-medium">DATE</th>
                <th className="px-4 py-3 font-medium">TIME</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {scans.map(scan => {
                const date = new Date(scan.created_at);
                return (
                  <tr key={scan.id} className="hover:bg-slate-800/50">
                    <td className="px-4 py-3 truncate max-w-[200px]" title={scan.url}>{scan.url}</td>
                    <td className="px-4 py-3 font-mono text-xs truncate max-w-[150px]" title={scan.user_id}>{scan.user_id}</td>
                    <td className="px-4 py-3 capitalize">{scan.scan_mode || 'Unknown'}</td>
                    <td className="px-4 py-3">{scan.score !== undefined && scan.score !== null ? scan.score : '-'}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs ${scan.status === 'completed' ? 'bg-green-500/20 text-green-300' : scan.status === 'failed' ? 'bg-red-500/20 text-red-300' : 'bg-blue-500/20 text-blue-300'}`}>
                        {scan.status || 'unknown'}
                      </span>
                    </td>
                    <td className="px-4 py-3">{date.toLocaleDateString()}</td>
                    <td className="px-4 py-3 text-slate-400">{date.toLocaleTimeString()}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
