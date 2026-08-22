import React, { useState, useEffect } from 'react';
import { History, ExternalLink, Calendar, ShieldAlert, Trash2, X } from 'lucide-react';
import { Link, Navigate, useNavigate } from 'react-router-dom';
import { supabase } from '../lib/supabase';
import { useAuth } from '../contexts/AuthContext';

const ScanHistory = () => {
  const { user, isAdmin } = useAuth();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [deletingId, setDeletingId] = useState(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState(null);
  const [deleteMessage, setDeleteMessage] = useState(null);
  const [selectedScans, setSelectedScans] = useState([]);
  const navigate = useNavigate();



  const getScanModeLabel = (mode) => {
    if (mode === 'active') return 'Advanced';
    if (mode === 'passive' || mode === 'basic') return 'Basic';
    return 'Unknown';
  };

  const getBaseScan = () => selectedScans.length > 0 ? selectedScans[0] : null;

  const isScanSelectable = (scan) => {
    const scanType = getScanModeLabel(scan.report_data?.scan_mode);
    if (scanType === 'Unknown') return false;

    if (selectedScans.some(s => s.id === scan.id)) return true;
    if (selectedScans.length >= 2) return false;

    const baseScan = getBaseScan();
    if (!baseScan) return true;

    const baseType = getScanModeLabel(baseScan.report_data?.scan_mode);
    const sameTarget = baseScan.target_url === scan.target_url;
    const sameType = baseType === scanType;

    return sameTarget && sameType;
  };

  const toggleSelection = (scan) => {
    if (selectedScans.some(s => s.id === scan.id)) {
      setSelectedScans(selectedScans.filter(s => s.id !== scan.id));
    } else {
      if (selectedScans.length < 2 && isScanSelectable(scan)) {
        setSelectedScans([...selectedScans, scan]);
      }
    }
  };

  const handleCompare = () => {
    if (selectedScans.length === 2) {
      navigate(`/history/compare?scan1=${selectedScans[0].id}&scan2=${selectedScans[1].id}`);
    }
  };

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

  useEffect(() => {
    if (!user) {
      setLoading(false);
      return;
    }
    fetchHistory();
  }, [user]);

  const handleDelete = async (id) => {
    setDeletingId(id);
    setDeleteMessage(null);
    try {
      const { error } = await supabase
        .from('scans')
        .delete()
        .eq('id', id);

      if (error) throw error;

      setScans(scans.filter(scan => scan.id !== id));
      setDeleteMessage({ type: 'success', text: 'Scan deleted.' });
      setTimeout(() => setDeleteMessage(null), 3000);
    } catch (err) {
      console.error('Error deleting scan:', err);
      setDeleteMessage({ type: 'error', text: 'Could not delete scan.' });
      setTimeout(() => setDeleteMessage(null), 3000);
    } finally {
      setDeletingId(null);
      setDeleteConfirmId(null);
    }
  };

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
      <div className="flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold text-slate-50 tracking-tight">Scan History</h1>
            <p className="text-slate-400 mt-1">Review all your previous security assessments.</p>
          </div>
          {isAdmin && (
            <button
              onClick={handleCompare}
              disabled={selectedScans.length !== 2}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              Compare Selected ({selectedScans.length})
            </button>
          )}
        </div>

      {deleteMessage && (
        <div className={`p-4 rounded-xl flex items-center gap-2 ${deleteMessage.type === 'success' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'}`}>
          {deleteMessage.text}
        </div>
      )}

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
                  <th className="p-4 font-medium w-12 text-center"></th>
                  <th className="p-4 font-medium">Target URL</th>
                  <th className="p-4 font-medium">Scan Type</th>
                  <th className="p-4 font-medium">Date</th>
                  <th className="p-4 font-medium">Time</th>
                  <th className="p-4 font-medium">Score</th>
                  <th className="p-4 font-medium text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {scans.map((scan) => {
                  const mode = scan.report_data?.scan_mode;
                  const modeLabel = mode === 'active' ? 'Advanced Scan' : (mode === 'passive' || mode === 'basic' ? 'Basic Scan' : 'Unknown');

                  const isSelected = selectedScans.some(s => s.id === scan.id);
                    const selectable = isScanSelectable(scan);

                    return (
                      <tr key={scan.id} className={`hover:bg-slate-800/30 transition-colors ${!selectable && !isSelected ? 'opacity-50 grayscale' : ''}`}>
                        <td className="p-4 text-center">
                          {isAdmin && (
                            <input
                              type="checkbox"
                              className="w-4 h-4 bg-slate-800 border-slate-600 rounded text-indigo-600 focus:ring-indigo-500 cursor-pointer disabled:cursor-not-allowed"
                              checked={isSelected}
                              disabled={!selectable && !isSelected}
                              onChange={() => toggleSelection(scan)}
                            />
                          )}
                        </td>
                        <td className="p-4 font-medium text-slate-50">
                          <span className="flex items-center gap-2">{scan.target_url}</span>
                        </td>
                        <td className="p-4 text-slate-400 whitespace-nowrap">
                          {modeLabel}
                        </td>
                      <td className="p-4 text-slate-400 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <Calendar className="w-4 h-4" />
                          {new Date(scan.created_at).toLocaleDateString()}
                        </div>
                      </td>
                      <td className="p-4 text-slate-400 whitespace-nowrap">
                        {new Date(scan.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </td>
                      <td className="p-4">
                        <div className={`inline-flex px-2 py-1 rounded text-xs font-bold ${scan.score >= 85 ? 'bg-emerald-500/10 text-emerald-400' : scan.score >= 70 ? 'bg-amber-500/10 text-amber-400' : 'bg-rose-500/10 text-rose-400'}`}>
                          {scan.score}
                        </div>
                      </td>
                      <td className="p-4 text-right">
                        <div className="flex items-center justify-end gap-4">
                          <Link to={`/history/${scan.id}`} className="inline-flex items-center gap-1 text-indigo-400 hover:text-indigo-300 transition-colors">
                            View Report <ExternalLink className="w-4 h-4" />
                          </Link>
                          <button
                            type="button"
                            onClick={() => setDeleteConfirmId(scan.id)}
                            className="inline-flex items-center gap-1 text-rose-500 hover:text-rose-400 transition-colors"
                            aria-label="Delete scan"
                          >
                            <Trash2 className="w-4 h-4" /> Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteConfirmId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl p-6 max-w-sm w-full shadow-2xl">
            <h3 className="text-xl font-bold text-slate-50 mb-2">Delete scan?</h3>
            <p className="text-slate-400 text-sm mb-6">
              Are you sure you want to delete this scan from your history? This action cannot be undone.
            </p>
            <div className="flex justify-end gap-3">
              <button
                type="button"
                onClick={() => setDeleteConfirmId(null)}
                className="px-4 py-2 text-sm font-semibold text-slate-300 hover:text-slate-50 transition-colors"
                disabled={deletingId !== null}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => handleDelete(deleteConfirmId)}
                disabled={deletingId !== null}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-sm font-semibold transition-colors disabled:opacity-50"
              >
                {deletingId ? 'Deleting...' : 'Delete'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanHistory;
