import React, { useState, useEffect } from 'react';
import { History, ExternalLink, Calendar, ShieldAlert } from 'lucide-react';
import { Link, Navigate } from 'react-router-dom';
import { supabase } from '../lib/supabase';
import { useAuth } from '../contexts/AuthContext';

const ScanHistory = () => {
  const { user } = useAuth();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!user) {
      setLoading(false);
      return;
    }

    const fetchHistory = async () => {
      try {
        const { data, error: err } = await supabase
          .from('scans')
          .select('*')
          .order('created_at', { ascending: false });

        if (err) throw err;
        setScans(data || []);
      } catch (err) {
        console.error('Error fetching history:', err);
        setError('Failed to load scan history.');
      } finally {
        setLoading(false);
      }
    };

    fetchHistory();
  }, [user]);

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (loading) {
    return (
      <div className="flex justify-center items-center h-[60vh]">
        <div className="text-slate-400">Loading history...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6 text-slate-200">
      <div>
        <h1 className="text-3xl font-bold text-slate-50 tracking-tight">Scan History</h1>
        <p className="text-slate-400 mt-1">Review all your previous security assessments.</p>
      </div>

      {error ? (
        <div className="bg-rose-500/10 border border-rose-500/30 p-4 rounded-xl text-rose-400 flex items-center gap-2">
          <ShieldAlert className="w-5 h-5" />
          {error}
        </div>
      ) : scans.length === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 text-center text-slate-400">
          You have no scan history yet. Try running your first scan!
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-800/50 border-b border-slate-700 text-slate-400 uppercase tracking-wider">
                <tr>
                  <th className="p-4 font-medium">Target URL</th>
                  <th className="p-4 font-medium">Date</th>
                  <th className="p-4 font-medium">Score</th>
                  <th className="p-4 font-medium text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {scans.map((scan) => {
                  const mode = scan.report_data?.scan_mode;
                  const modeLabel = mode === 'active' ? 'Advanced Scan' : (mode === 'passive' || mode === 'basic' ? 'Basic Scan' : 'Unknown');
                  
                  return (
                    <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="p-4 font-medium text-slate-50">
                        <div className="flex flex-col">
                          <span className="flex items-center gap-2">{scan.target_url}</span>
                          <span className="text-xs text-slate-400 mt-1">{modeLabel}</span>
                        </div>
                      </td>
                      <td className="p-4 text-slate-400 flex items-center gap-2">
                        <Calendar className="w-4 h-4" />
                        {new Date(scan.created_at).toLocaleDateString()}
                      </td>
                      <td className="p-4">
                        <div className={`inline-flex px-2 py-1 rounded text-xs font-bold ${scan.score >= 85 ? 'bg-emerald-500/10 text-emerald-400' : scan.score >= 70 ? 'bg-amber-500/10 text-amber-400' : 'bg-rose-500/10 text-rose-400'}`}>
                          {scan.score}
                        </div>
                      </td>
                      <td className="p-4 text-right">
                        <Link to={`/history/${scan.id}`} className="inline-flex items-center gap-1 text-indigo-400 hover:text-indigo-300">
                          View Report <ExternalLink className="w-4 h-4" />
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanHistory;
