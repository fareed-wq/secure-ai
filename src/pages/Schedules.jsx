import React, { useState, useEffect, useRef } from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { CalendarDays, Plus, Trash2, Pause, Play, AlertCircle, CheckCircle2, ChevronRight, Loader2 } from 'lucide-react';
import { useSEO } from '../hooks/useSEO';

export default function Schedules() {
  useSEO({
    title: 'Schedule Scans | URLScan Online',
    description: 'Manage automated recurring security scans.',
    path: '/schedules'
  });

  const { canUseScheduledScans, loading, isAdminLoading, session } = useAuth();
  const [schedules, setSchedules] = useState([]);
  const [isCreating, setIsCreating] = useState(false);
  const [isInitialLoading, setIsInitialLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [pendingActions, setPendingActions] = useState({});
  const createPendingRef = useRef(false);
  const actionPendingRef = useRef(new Set());

  // Form State
  const [targetUrl, setTargetUrl] = useState('');
  const [scanMode, setScanMode] = useState('passive');
  const [emailReportEnabled, setEmailReportEnabled] = useState(false);
  const [advancedAuthChecked, setAdvancedAuthChecked] = useState(false);
  const [frequency, setFrequency] = useState('daily');
  const [timeOfDay, setTimeOfDay] = useState('09:00');
  const [timezone, setTimezone] = useState(Intl.DateTimeFormat().resolvedOptions().timeZone);
  const [dayOfWeek, setDayOfWeek] = useState(0);
  const [dayOfMonth, setDayOfMonth] = useState(1);
  const [authChecked, setAuthChecked] = useState(false);

  useEffect(() => {
    if (canUseScheduledScans && session) {
      fetchSchedules();
    }
  }, [canUseScheduledScans, session]);

  const fetchSchedules = async () => {
    setLoadError(false);
    setIsInitialLoading(true);
    try {
      const res = await fetch('/api/schedules', {
        headers: { Authorization: `Bearer ${session.access_token}` }
      });
      if (res.ok) {
        setSchedules(await res.json());
      } else {
        setLoadError(true);
      }
    } catch (e) {
      console.error(e);
      setLoadError(true);
    } finally {
      setIsInitialLoading(false);
    }
  };

  const authLoading = loading || isAdminLoading;

  if (authLoading) {
    return (
      <div className="space-y-6">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <div>
            <h1 className="text-2xl font-bold text-slate-50 flex items-center gap-2">
              <CalendarDays className="text-indigo-400" />
              Schedule Scans
            </h1>
            <p className="text-slate-400 mt-1">
              Automatically run recurring security scans on authorized targets.
            </p>
          </div>
        </div>
        <div className="grid grid-cols-1 gap-4" aria-busy="true">
          {[1, 2].map(i => (
            <div key={i} className="bg-slate-900 border border-slate-800 rounded-2xl p-6 h-32 animate-pulse" />
          ))}
        </div>
      </div>
    );
  }

  if (!canUseScheduledScans) {
    return <Navigate to="/dashboard" replace />;
  }

  const handleCreate = async (e) => {
    e.preventDefault();
    if (!authChecked || isSaving || createPendingRef.current) return;
    createPendingRef.current = true;
    setIsSaving(true);

    try {
      const res = await fetch('/api/schedules', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.access_token}`
        },
        body: JSON.stringify({
          target_url: targetUrl,
          scan_mode: scanMode,
          advanced_authorization_acknowledged: advancedAuthChecked,
        email_report_enabled: emailReportEnabled,
          frequency,
          time_of_day: timeOfDay + ':00',
          timezone,
          day_of_week: frequency === 'weekly' ? parseInt(dayOfWeek) : null,
          day_of_month: frequency === 'monthly' ? parseInt(dayOfMonth) : null,
          authorization_acknowledged: authChecked
        })
      });
      if (res.ok) {
        setIsCreating(false);
        fetchSchedules();
      }
    } catch (e) {
      console.error(e);
    } finally {
      createPendingRef.current = false;
      setIsSaving(false);
    }
  };

  const handleDelete = async (id) => {
    if (pendingActions[id] || actionPendingRef.current.has(id)) return;
    if (!window.confirm('Deleting this schedule stops future scans. Previous scan history will remain.')) return;
    actionPendingRef.current.add(id);
    setPendingActions(prev => ({ ...prev, [id]: 'delete' }));
    try {
      const res = await fetch(`/api/schedules/${id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${session.access_token}` }
      });
      if (res.ok) fetchSchedules();
    } catch (e) {
      console.error(e);
    } finally {
      actionPendingRef.current.delete(id);
      setPendingActions(prev => { const next = {...prev}; delete next[id]; return next; });
    }
  };

  const handleToggle = async (sched) => {
    if (pendingActions[sched.id] || actionPendingRef.current.has(sched.id)) return;
    actionPendingRef.current.add(sched.id);
    try {
      const action = sched.is_enabled ? 'pause' : 'resume';
      setPendingActions(prev => ({ ...prev, [sched.id]: action }));
      const res = await fetch(`/api/schedules/${sched.id}/${action}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${session.access_token}` }
      });
      if (res.ok) fetchSchedules();
    } catch (e) {
      console.error(e);
    } finally {
      actionPendingRef.current.delete(sched.id);
      setPendingActions(prev => { const next = {...prev}; delete next[sched.id]; return next; });
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-50 flex items-center gap-2">
            <CalendarDays className="text-indigo-400" />
            Schedule Scans
          </h1>
          <p className="text-slate-400 mt-1">
            Automatically run recurring security scans on authorized targets.
          </p>
        </div>
        {!isCreating && schedules.length < 3 && (
          <button
            onClick={() => setIsCreating(true)}
            className="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
          >
            <Plus size={16} />
            Create Schedule
          </button>
        )}
        {!isCreating && schedules.length >= 3 && (
          <p className="text-amber-400 text-sm bg-amber-400/10 px-3 py-1.5 rounded-lg border border-amber-400/20">
            Maximum of 3 scheduled scans reached.
          </p>
        )}
      </div>

      {isCreating && (
        <form onSubmit={handleCreate} className="bg-slate-900 border border-slate-800 rounded-2xl p-6 md:p-8 max-w-2xl">
          <h2 className="text-xl font-bold text-slate-50 mb-6">Create New Schedule</h2>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Target URL</label>
              <input
                type="url" required value={targetUrl} onChange={e => setTargetUrl(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-slate-200 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none"
                placeholder="https://example.com"
              />
            </div>



            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Frequency</label>
                <select value={frequency} onChange={e => setFrequency(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-slate-200 focus:ring-2 focus:ring-indigo-500 outline-none"
                >
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                </select>
              </div>

              {frequency === 'weekly' && (
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1">Day of Week</label>
                  <select value={dayOfWeek} onChange={e => setDayOfWeek(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-slate-200 focus:ring-2 focus:ring-indigo-500 outline-none"
                  >
                    <option value={0}>Monday</option>
                    <option value={1}>Tuesday</option>
                    <option value={2}>Wednesday</option>
                    <option value={3}>Thursday</option>
                    <option value={4}>Friday</option>
                    <option value={5}>Saturday</option>
                    <option value={6}>Sunday</option>
                  </select>
                </div>
              )}

              {frequency === 'monthly' && (
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1">Day of Month (1-28)</label>
                  <input type="number" min="1" max="28" required value={dayOfMonth} onChange={e => setDayOfMonth(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-slate-200 focus:ring-2 focus:ring-indigo-500 outline-none"
                  />
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Local Time</label>
                <input type="time" required value={timeOfDay} onChange={e => setTimeOfDay(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-slate-200 focus:ring-2 focus:ring-indigo-500 outline-none"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Timezone</label>
                <input type="text" required value={timezone} onChange={e => setTimezone(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-slate-200 focus:ring-2 focus:ring-indigo-500 outline-none"
                />
              </div>
            </div>

            <div className="pt-4">
              <label className="block text-sm font-medium text-slate-300 mb-2">Scan Type</label>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <label className={`relative flex cursor-pointer rounded-lg border bg-slate-900/50 p-4 focus:outline-none ${scanMode === 'passive' ? 'border-indigo-500 ring-1 ring-indigo-500' : 'border-slate-700 hover:border-slate-600'}`}>
                  <input type="radio" name="scanMode" value="passive" className="sr-only" checked={scanMode === 'passive'} onChange={() => { setScanMode('passive'); setAdvancedAuthChecked(false); }} />
                  <span className="flex flex-col">
                    <span className="block text-sm font-medium text-slate-50">Basic (Passive)</span>
                    <span className="mt-1 flex items-center text-sm text-slate-400">Low-impact passive security checks.</span>
                  </span>
                  <span className={`pointer-events-none absolute -inset-px rounded-lg border-2 ${scanMode === 'passive' ? 'border-indigo-500' : 'border-transparent'}`} aria-hidden="true"></span>
                </label>
                <label className={`relative flex cursor-pointer rounded-lg border bg-slate-900/50 p-4 focus:outline-none ${scanMode === 'active' ? 'border-indigo-500 ring-1 ring-indigo-500' : 'border-slate-700 hover:border-slate-600'}`}>
                  <input type="radio" name="scanMode" value="active" className="sr-only" checked={scanMode === 'active'} onChange={() => setScanMode('active')} />
                  <span className="flex flex-col">
                    <span className="block text-sm font-medium text-slate-50">Advanced</span>
                    <span className="mt-1 flex items-center text-sm text-slate-400">Includes additional bounded HTTP, DNS, and network checks.</span>
                  </span>
                  <span className={`pointer-events-none absolute -inset-px rounded-lg border-2 ${scanMode === 'active' ? 'border-indigo-500' : 'border-transparent'}`} aria-hidden="true"></span>
                </label>
              </div>
            </div>

            <div className="pt-4 space-y-4">
              <label className="flex items-start gap-3 cursor-pointer">
                <input type="checkbox" required checked={authChecked} onChange={e => setAuthChecked(e.target.checked)}
                  className="mt-1 w-4 h-4 bg-slate-950 border-slate-700 rounded text-indigo-600 focus:ring-indigo-500"
                />
                <span className="text-sm text-slate-300">
                  I confirm I am authorized to scan this target and will maintain authorization while this schedule is active.
                </span>
              </label>

              {scanMode === 'active' && (
                <label className="flex items-start gap-3 cursor-pointer">
                  <input type="checkbox" required checked={advancedAuthChecked} onChange={e => setAdvancedAuthChecked(e.target.checked)}
                    className="mt-1 w-4 h-4 bg-slate-950 border-slate-700 rounded text-indigo-600 focus:ring-indigo-500"
                  />
                  <span className="text-sm text-slate-300 font-medium">
                    I confirm I am authorized to perform recurring advanced security testing against this target.
                  </span>
                </label>
              )}
              
              <label className="flex items-start gap-3 cursor-pointer mt-4">
                <input type="checkbox" checked={emailReportEnabled} onChange={e => setEmailReportEnabled(e.target.checked)}
                  className="mt-1 w-4 h-4 bg-slate-950 border-slate-700 rounded text-indigo-600 focus:ring-indigo-500"
                />
                <div className="flex flex-col">
                  <span className="text-sm text-slate-300 font-medium">
                    Email PDF report after each completed scan
                  </span>
                  <span className="text-sm text-slate-500 mt-1">
                    The completed report will be sent to your verified account email.
                  </span>
                </div>
              </label>
            </div>

            <div className="flex justify-end gap-3 pt-4">
              <button type="button" onClick={() => setIsCreating(false)} disabled={isSaving} className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
                Cancel
              </button>
              <button type="submit" disabled={!authChecked || (scanMode === 'active' && !advancedAuthChecked) || isSaving} className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed text-white px-6 py-2 rounded-lg text-sm font-medium transition-colors flex items-center justify-center min-w-[140px]">
                {isSaving ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Saving...</> : 'Save Schedule'}
              </button>
            </div>
          </div>
        </form>
      )}

      {isInitialLoading && !isCreating && (
        <div className="grid grid-cols-1 gap-4" aria-busy="true">
          {[1, 2].map(i => (
            <div key={i} className="bg-slate-900 border border-slate-800 rounded-2xl p-6 h-32 animate-pulse" />
          ))}
        </div>
      )}

      {loadError && !isInitialLoading && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center flex flex-col items-center justify-center">
          <AlertCircle className="w-12 h-12 text-rose-500 mb-4" />
          <h3 className="text-xl font-bold text-slate-200 mb-2">Unable to load scheduled scans</h3>
          <p className="text-slate-400 mb-6 max-w-md">
            There was a problem loading your schedules. Please try again.
          </p>
          <button onClick={fetchSchedules} className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-6 py-2 rounded-lg font-medium transition-colors border border-slate-700">
            Retry
          </button>
        </div>
      )}

      {!isInitialLoading && !loadError && !isCreating && schedules.length === 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center flex flex-col items-center justify-center">
          <CalendarDays className="w-16 h-16 text-slate-700 mb-4" />
          <h3 className="text-xl font-bold text-slate-200 mb-2">No scheduled scans yet.</h3>
          <p className="text-slate-400 mb-6 max-w-md">
            Create a recurring security scan for an authorized target.
          </p>
          <button onClick={() => setIsCreating(true)} className="bg-indigo-600 hover:bg-indigo-500 text-white px-6 py-2 rounded-lg font-medium transition-colors">
            Create Schedule
          </button>
        </div>
      )}

      {!isInitialLoading && !loadError && !isCreating && schedules.length > 0 && (
        <div className="grid grid-cols-1 gap-4">
          {schedules.map(sched => (
            <div key={sched.id} className="bg-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
              <div className="flex-1 space-y-2">
                <div className="flex items-center gap-3">
                  <h3 className="text-lg font-bold text-slate-50">{sched.target_url}</h3>
                  <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border ${sched.is_enabled ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-slate-800 text-slate-400 border-slate-700'}`}>
                    {sched.is_enabled ? 'Active' : 'Paused'}
                  </span>
                  <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border ${sched.scan_mode === 'active' ? 'bg-fuchsia-500/10 text-fuchsia-400 border-fuchsia-500/20' : 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20'}`}>
                    {sched.scan_mode === 'active' ? 'Advanced' : 'Basic'}
                  </span>
                </div>
                <div className="text-sm text-slate-400 flex flex-wrap gap-x-6 gap-y-1">
                  <span><strong className="text-slate-300">Freq:</strong> <span className="capitalize">{sched.frequency}</span> at {sched.time_of_day.substring(0, 5)}</span>
                  <span><strong className="text-slate-300">TZ:</strong> {sched.timezone}</span>
                  {sched.next_run_at && <span><strong className="text-slate-300">Next:</strong> {new Date(sched.next_run_at).toLocaleString()}</span>}
                </div>
                {sched.last_run_at && (
                  <div className="text-xs text-slate-500 flex items-center gap-2">
                    <span>Last run: {new Date(sched.last_run_at).toLocaleString()}</span>
                    {sched.last_status === 'completed' && <CheckCircle2 size={14} className="text-emerald-500" />}
                    {sched.last_status === 'failed' && <AlertCircle size={14} className="text-rose-500" />}
                    <span>({sched.last_status})</span>
                    {sched.email_report_enabled && sched.latest_email_status && (
                      <span className="ml-2 pl-2 border-l border-slate-700">
                        Email: {sched.latest_email_status.charAt(0).toUpperCase() + sched.latest_email_status.slice(1)}
                      </span>
                    )}
                  </div>
                )}
              </div>

              <div className="flex items-center gap-2 w-full md:w-auto border-t border-slate-800 md:border-none pt-4 md:pt-0">
                <button onClick={() => handleToggle(sched)} disabled={!!pendingActions[sched.id]} aria-disabled={!!pendingActions[sched.id]} aria-busy={!!pendingActions[sched.id]} className="p-2 text-slate-400 hover:text-slate-50 transition-colors bg-slate-800 hover:bg-slate-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed w-9 h-9 flex items-center justify-center">
                  {pendingActions[sched.id] === 'pause' || pendingActions[sched.id] === 'resume' ? <Loader2 size={18} className="animate-spin text-indigo-400" /> : (sched.is_enabled ? <Pause size={18} /> : <Play size={18} />)}
                </button>
                <button onClick={() => handleDelete(sched.id)} disabled={!!pendingActions[sched.id]} aria-disabled={!!pendingActions[sched.id]} aria-busy={!!pendingActions[sched.id]} className="p-2 text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 transition-colors bg-slate-800 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed w-9 h-9 flex items-center justify-center">
                  {pendingActions[sched.id] === 'delete' ? <Loader2 size={18} className="animate-spin" /> : <Trash2 size={18} />}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

