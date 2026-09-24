import React, { useState, useEffect } from 'react';
import { History, ExternalLink, Calendar, ShieldAlert, Trash2, X, Search } from 'lucide-react';
import { Link, Navigate, useNavigate } from 'react-router-dom';
import { supabase } from '../lib/supabase';
import { useAuth } from '../contexts/AuthContext';


const normalizeForCompare = (url) => {
  try {
    const parsed = new URL(url);
    let path = parsed.pathname;
    if (path === '/') path = '';
    return `${parsed.protocol}//${parsed.hostname}${parsed.port ? ':' + parsed.port : ''}${path}${parsed.search}`;
  } catch (e) {
    return url;
  }
};

const ScanHistory = () => {
  const { user, canUseScanCompare } = useAuth();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [deletingId, setDeletingId] = useState(null);
  const [deleteConfirmState, setDeleteConfirmState] = useState(null);
  const [deleteMessage, setDeleteMessage] = useState(null);
  const [selectedScans, setSelectedScans] = useState([]);
  const navigate = useNavigate();

  const [searchTerm, setSearchTerm] = useState('');
  const [searchInput, setSearchInput] = useState('');

  useEffect(() => {
    const delayDebounceFn = setTimeout(() => {
      setSearchTerm(searchInput);
    }, 300);
    return () => clearTimeout(delayDebounceFn);
  }, [searchInput]);

  const getScanModeLabel = (mode) => {
    if (mode === 'active') return 'Advanced';
    if (mode === 'passive' || mode === 'basic') return 'Basic';
    return 'Unknown';
  };

  const filteredScans = scans.filter(scan => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    const typeLabel = getScanModeLabel(scan.report_data?.scan_mode).toLowerCase();
    const targetUrl = (scan.target_url || '').toLowerCase();
    const scoreStr = (scan.score || '').toString();
    return targetUrl.includes(term) || typeLabel.includes(term) || scoreStr.includes(term);
  });

  const canCompare = () => {
    if (selectedScans.length !== 2) return false;
    const scanType1 = getScanModeLabel(selectedScans[0].report_data?.scan_mode);
    const scanType2 = getScanModeLabel(selectedScans[1].report_data?.scan_mode);

    if (scanType1 === 'Unknown' || scanType2 === 'Unknown') return false;

    const sameTarget = normalizeForCompare(selectedScans[0].target_url) === normalizeForCompare(selectedScans[1].target_url);
    const sameType = scanType1 === scanType2;

    return sameTarget && sameType;
  };

  const toggleSelection = (scan) => {
    if (selectedScans.some(s => s.id === scan.id)) {
      setSelectedScans(selectedScans.filter(s => s.id !== scan.id));
    } else {
      setSelectedScans([...selectedScans, scan]);
    }
  };

  const handleCompare = () => {
    if (!canCompare()) return;
    navigate(`/history/compare?scan1=${selectedScans[0].id}&scan2=${selectedScans[1].id}`);
  };

  const fetchHistory = async () => {
    try {
      const { data, error: err } = await supabase
        .from('scans')
          .select('id, target_url, score, created_at, status, trigger_type, scan_mode:report_data->>scan_mode')
          .eq('user_id', user.id)
          .order('created_at', { ascending: false });

      if (err) throw err;

      const mappedData = (data || []).map(row => ({
        ...row,
        report_data: { scan_mode: row.scan_mode }
      }));

      setScans(mappedData);
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

  const executeDelete = async () => {
    if (!deleteConfirmState) return;

    setDeletingId(true);
    setDeleteMessage(null);
    try {
      if (deleteConfirmState.action === 'single') {
        const id = deleteConfirmState.payload;
        const { error } = await supabase
          .from('scans')
          .delete()
          .eq('user_id', user.id)
          .eq('id', id);

        if (error) throw error;

        setScans(scans.filter(scan => scan.id !== id));
        setSelectedScans(selectedScans.filter(scan => scan.id !== id));
      } else if (deleteConfirmState.action === 'selected') {
        const idsToDelete = deleteConfirmState.payload.map(s => s.id);
        const { error } = await supabase
          .from('scans')
          .delete()
          .eq('user_id', user.id)
          .in('id', idsToDelete);

        if (error) throw error;

        setScans(scans.filter(scan => !idsToDelete.includes(scan.id)));
        setSelectedScans([]);
      } else if (deleteConfirmState.action === 'all') {
        const { error } = await supabase
          .from('scans')
          .delete()
          .eq('user_id', user.id);

        if (error) throw error;

        setScans([]);
        setSelectedScans([]);
      }

      setDeleteMessage({ type: 'success', text: 'Scan(s) deleted.' });
      setTimeout(() => setDeleteMessage(null), 3000);
    } catch (err) {
      console.error('Error deleting scan(s):', err);
      setDeleteMessage({ type: 'error', text: 'Could not delete scan(s).' });
      setTimeout(() => setDeleteMessage(null), 3000);
    } finally {
      setDeletingId(null);
      setDeleteConfirmState(null);
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
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold text-slate-50 tracking-tight">Scan History</h1>
          <p className="text-slate-400 mt-1">Review all your previous security assessments.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {canUseScanCompare && (
            <button
              onClick={handleCompare}
              disabled={!canCompare()}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-900"
            >
              Compare Selected ({selectedScans.length})
            </button>
          )}
          <button
            onClick={() => setDeleteConfirmState({ action: 'selected', payload: selectedScans })}
            disabled={selectedScans.length === 0}
            className="px-4 py-2 bg-rose-600/20 text-rose-400 hover:bg-rose-600/30 border border-rose-500/30 rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-900"
          >
            Delete Selected
          </button>
          {scans.length > 0 && (
            <button
              onClick={() => setDeleteConfirmState({ action: 'all', payload: scans.length })}
              className="px-4 py-2 bg-rose-600/20 text-rose-400 hover:bg-rose-600/30 border border-rose-500/30 rounded-lg font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-900"
            >
              Delete All History
            </button>
          )}
        </div>
      </div>


      {scans.length > 0 || searchTerm ? (
        <div className="mb-6 relative max-w-md">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
          <input
            type="text"
            className="w-full bg-slate-800/50 border border-slate-700 rounded-lg pl-9 pr-10 py-2 text-sm text-slate-200 placeholder-slate-400 focus:outline-none focus:border-indigo-500 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
            placeholder="Search history by target or scan type..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
          {searchInput && (
            <button
              onClick={() => { setSearchInput(''); setSearchTerm(''); }}
              className="absolute right-3 top-2.5 text-slate-400 hover:text-white" aria-label="Clear search"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>
      ) : null}

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
      ) : filteredScans.length === 0 ? (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center flex flex-col items-center justify-center">
            <div className="w-16 h-16 bg-slate-800/50 rounded-full flex items-center justify-center mb-4 text-slate-400">
              <Search className="w-8 h-8" />
            </div>
            <h2 className="text-lg font-bold text-slate-200 mb-2">{searchTerm ? 'No Results Found' : 'No Scan History'}</h2>
            <p className="text-slate-400 text-sm max-w-md mx-auto">{searchTerm ? 'Try adjusting your search terms or filters.' : 'You have no scan history yet. Run a new scan from the dashboard to get started.'}</p>
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
                {filteredScans.map((scan) => {
                  const mode = scan.report_data?.scan_mode;
                  const modeLabel = mode === 'active' ? 'Advanced Scan' : (mode === 'passive' || mode === 'basic' ? 'Basic Scan' : 'Unknown');

                  const isSelected = selectedScans.some(s => s.id === scan.id);

                  return (
                    <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="p-4 text-center">
                        <input
                          type="checkbox"
                          className="w-4 h-4 bg-slate-800 border-slate-600 rounded text-indigo-600 focus:ring-indigo-500 cursor-pointer"
                          checked={isSelected}
                          onChange={() => toggleSelection(scan)}
                          aria-label={`Select scan for ${scan.target_url}`}
                        />
                      </td>
                        <td className="p-4 font-medium text-slate-50">
                          <span className="flex items-center gap-2">
                            {scan.target_url}
                            {scan.trigger_type === 'scheduled' && (
                              <span className="text-[10px] font-semibold tracking-wide uppercase px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">Scheduled</span>
                            )}
                          </span>
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
                          <Link to={`/history/${scan.id}?from=history`} className="inline-flex items-center gap-1 text-indigo-400 hover:text-indigo-300 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-900">
                            View Report <ExternalLink className="w-4 h-4" />
                          </Link>
                          <button
                            type="button"
                            onClick={() => setDeleteConfirmState({ action: 'single', payload: scan.id })}
                            className="inline-flex items-center gap-1 text-rose-500 hover:text-rose-400 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-900"
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
      {deleteConfirmState && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl p-6 max-w-sm w-full shadow-lg">
            <h3 className="text-xl font-bold text-slate-50 mb-2">Delete scan{deleteConfirmState.action !== 'single' ? 's' : ''}?</h3>
            <p className="text-slate-400 text-sm mb-6">
              {deleteConfirmState.action === 'single' && "Are you sure you want to delete this scan from your history? This action cannot be undone."}
              {deleteConfirmState.action === 'selected' && `Are you sure you want to delete these ${deleteConfirmState.payload.length} selected scans from your history? This action cannot be undone.`}
              {deleteConfirmState.action === 'all' && `Are you sure you want to delete ALL ${deleteConfirmState.payload} scans from your history? This action cannot be undone.`}
            </p>
            <div className="flex justify-end gap-3">
              <button
                type="button"
                onClick={() => setDeleteConfirmState(null)}
                className="px-4 py-2 text-sm font-semibold text-slate-300 hover:text-slate-50 transition-colors"
                disabled={deletingId !== null}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={executeDelete}
                disabled={deletingId !== null}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-sm font-semibold transition-colors disabled:opacity-50"
              >
                {deletingId ? 'Deleting...' : (deleteConfirmState.action === 'selected' ? 'Delete Selected' : (deleteConfirmState.action === 'all' ? 'Delete All' : 'Delete'))}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanHistory;
