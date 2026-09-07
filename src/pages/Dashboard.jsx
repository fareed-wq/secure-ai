import React, { useState, useEffect, useMemo } from 'react';
import { ShieldCheck, Activity, Target, AlertTriangle, Loader2, CheckCircle2, ChevronRight, Plus, AlertCircle, Info } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { useAuth } from "../contexts/AuthContext";
import { supabase } from '../lib/supabase';
import { useNavigate, Link } from 'react-router-dom';

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    return (
      <div className="bg-slate-900 border border-slate-700 p-3 rounded-lg shadow-xl">
        <p className="text-slate-50 font-medium mb-1">{data.domain}</p>
        <p className="text-slate-400 text-xs mb-2">{data.timestamp}</p>
        <p className="text-indigo-400 font-bold">Score: {data.score}/100</p>
      </div>
    );
  }
  return null;
};

// Target Normalization: preserve subdomain/www, preserve non-default port, drop scheme/path/query
const getDomain = (url) => {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();
    const port = parsed.port;
    return port ? `${host}:${port}` : host;
  } catch {
    return url;
  }
};

const getSeverityColor = (severity) => {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'text-rose-500';
    case 'high': return 'text-rose-400';
    case 'medium': return 'text-amber-400';
    case 'low': return 'text-blue-400';
    default: return 'text-slate-400';
  }
};

const formatDateCompact = (d) => {
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) + ', ' + d.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' });
};

const Dashboard = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedTarget, setSelectedTarget] = useState('');
  const [selectedMode, setSelectedMode] = useState('active');

  useEffect(() => {
    const fetchScans = async () => {
      if (!user) {
        setLoading(false);
        return;
      }
      const { data, error } = await supabase
        .from('scans')
        .select('*')
        .eq('user_id', user.id)
        .order('created_at', { ascending: false });

      if (error) {
        console.error("Error fetching scans", error);
      } else {
        setScans(data || []);
      }
      setLoading(false);
    };

    fetchScans();
  }, [user]);

  // Derived KPIs
  const totalScans = scans.length;

  // Latest scan per unique target preferring Advanced mode
  const latestScansByTarget = useMemo(() => {
    const map = new Map();
    scans.forEach(scan => {
      if (scan.status === 'failed' || scan.status === 'error' || !scan.report_data) return; // only completed scans

      const domain = getDomain(scan.target_url);
      const currentMode = scan.report_data?.scan_mode === 'active' ? 'active' : 'passive';

      if (!map.has(domain)) {
        map.set(domain, scan);
      } else {
        const existingScan = map.get(domain);
        const existingMode = existingScan.report_data?.scan_mode === 'active' ? 'active' : 'passive';
        // Prefer latest completed Advanced scan over a newer Basic scan
        if (existingMode === 'passive' && currentMode === 'active') {
          map.set(domain, scan);
        }
      }
    });
    return map;
  }, [scans]);

  const uniqueTargets = latestScansByTarget.size;
  const latestScans = Array.from(latestScansByTarget.values());

  const portfolioScore = uniqueTargets > 0
    ? Math.round(latestScans.reduce((acc, curr) => acc + curr.score, 0) / uniqueTargets)
    : '--';

  // Total severity findings from latest posture scans
  let totalCritical = 0;
  let totalHigh = 0;
  let totalMedium = 0;
  let totalLow = 0;
  let totalInfo = 0;

  const needsAttention = [];

  latestScans.forEach(scan => {
    const findings = scan.report_data?.findings || [];

    findings.forEach(f => {
      if (f.severity === 'Critical') {
        totalCritical++;
        needsAttention.push({ target: getDomain(scan.target_url), scanId: scan.id, ...f });
      }
      else if (f.severity === 'High') {
        totalHigh++;
        needsAttention.push({ target: getDomain(scan.target_url), scanId: scan.id, ...f });
      }
      else if (f.severity === 'Medium') {
        totalMedium++;
        needsAttention.push({ target: getDomain(scan.target_url), scanId: scan.id, ...f });
      }
      else if (f.severity === 'Low') {
        totalLow++;
      }
      else {
        totalInfo++;
      }
    });
  });

  // Sort needsAttention: Critical > High > Medium
  const severityValue = { 'Critical': 3, 'High': 2, 'Medium': 1 };
  needsAttention.sort((a, b) => (severityValue[b.severity] || 0) - (severityValue[a.severity] || 0));
  const topAttention = needsAttention.slice(0, 5);

  const totalHighCritical = totalCritical + totalHigh;

  // Set default selected target and mode on load
  useEffect(() => {
    if (!selectedTarget && latestScans.length > 0) {
      const initialTarget = getDomain(latestScans[0].target_url);
      setSelectedTarget(initialTarget);
    }
  }, [latestScans, selectedTarget]);

  const targetModes = useMemo(() => {
    if (!selectedTarget) return new Set(['passive']);
    const modes = new Set();
    scans.forEach(s => {
      if (getDomain(s.target_url) === selectedTarget && s.report_data) {
        modes.add(s.report_data.scan_mode === 'active' ? 'active' : 'passive');
      }
    });
    return modes;
  }, [scans, selectedTarget]);

  useEffect(() => {
    if (selectedTarget) {
      const preferredScan = latestScansByTarget.get(selectedTarget);
      const preferredMode = preferredScan?.report_data?.scan_mode === 'active' ? 'active' : 'passive';
      setSelectedMode(preferredMode);
    }
  }, [selectedTarget, latestScansByTarget]);

  // Trend Data for Selected Target AND Selected Mode
  const trendData = useMemo(() => {
    if (!selectedTarget) return [];
    const targetScans = scans.filter(s => {
      const isTarget = getDomain(s.target_url) === selectedTarget;
      const isCompleted = !!s.report_data && s.status !== 'failed' && s.status !== 'error';
      const scanMode = s.report_data?.scan_mode === 'active' ? 'active' : 'passive';
      return isTarget && isCompleted && scanMode === selectedMode;
    });

    return targetScans.reverse().map((scan) => {
      const d = new Date(scan.created_at);
      return {
        timestamp: formatDateCompact(d),
        score: scan.score,
        domain: selectedTarget
      };
    });
  }, [scans, selectedTarget, selectedMode]);

  const handleNewScan = () => {
    navigate('/', { state: { resetScan: Date.now() } });
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold text-slate-50 tracking-tight">Overview</h1>
          <p className="text-slate-400 mt-1">Welcome back, {user?.user_metadata?.full_name || user?.email || 'Demo User'}</p>
        </div>
        <button
          onClick={handleNewScan}
          className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-medium rounded-lg flex items-center transition-colors gap-2"
        >
          <Plus size={18} /> New Scan
        </button>
      </div>

      {loading ? (
        <div className="flex justify-center items-center py-20">
          <Loader2 className="w-8 h-8 text-indigo-500 animate-spin" />
        </div>
      ) : (
        <>
          {/* KPI Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex items-start justify-between">
              <div>
                <p className="text-sm font-medium text-slate-400 uppercase tracking-wider">Portfolio Score</p>
                <p className="text-3xl font-bold text-emerald-400 mt-2">{portfolioScore}{portfolioScore !== '--' ? '/100' : ''}</p>
                <p className="text-xs text-slate-500 mt-2">Latest posture scan per target</p>
              </div>
              <div className="p-3 bg-emerald-500/10 rounded-lg"><ShieldCheck className="w-6 h-6 text-emerald-500" /></div>
            </div>

            <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex items-start justify-between">
              <div>
                <p className="text-sm font-medium text-slate-400 uppercase tracking-wider">Unique Targets</p>
                <p className="text-3xl font-bold text-blue-400 mt-2">{uniqueTargets}</p>
                <p className="text-xs text-slate-500 mt-2">From completed scans</p>
              </div>
              <div className="p-3 bg-blue-500/10 rounded-lg"><Target className="w-6 h-6 text-blue-500" /></div>
            </div>

            <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex items-start justify-between">
              <div>
                <p className="text-sm font-medium text-slate-400 uppercase tracking-wider">
                  {totalCritical > 0 ? 'High / Critical' : 'High Findings'}
                </p>
                <p className={`text-3xl font-bold mt-2 ${totalHighCritical === 0 ? 'text-emerald-400' : 'text-rose-400'}`}>
                  {totalCritical > 0 ? totalHighCritical : totalHigh}
                </p>
                <p className="text-xs text-slate-400 mt-2 font-medium">
                  {totalCritical > 0 ? `${totalCritical} Critical · ${totalHigh} High` : 'Across latest posture scans'}
                </p>
              </div>
              <div className={`p-3 rounded-lg border ${
                totalHighCritical === 0
                ? 'bg-emerald-500/10 border-emerald-500/20'
                : 'bg-rose-500/10 border-rose-500/20'
              }`}>
                {totalHighCritical === 0 ? (
                  <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                ) : (
                  <AlertTriangle className="w-6 h-6 text-rose-400" />
                )}
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex items-start justify-between">
              <div>
                <p className="text-sm font-medium text-slate-400 uppercase tracking-wider">Total Scans</p>
                <p className="text-3xl font-bold text-indigo-400 mt-2">{totalScans}</p>
                <p className="text-xs text-slate-500 mt-2">Historical count</p>
              </div>
              <div className="p-3 bg-indigo-500/10 rounded-lg"><Activity className="w-6 h-6 text-indigo-500" /></div>
            </div>
          </div>

          {/* Charts & Summary Section */}
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
            <div className="lg:col-span-3 bg-slate-900 border border-slate-800 p-6 rounded-2xl">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-6 gap-4">
                <h2 className="text-lg font-semibold text-slate-50">Security Score Trend</h2>
                <div className="flex flex-wrap items-center gap-4">
                  <div className="flex items-center gap-2">
                    <label htmlFor="target-select" className="text-sm text-slate-400">Target:</label>
                    <select
                      id="target-select"
                      className="bg-slate-950 border border-slate-800 text-slate-300 text-sm rounded-lg focus:ring-indigo-500 focus:border-indigo-500 p-2"
                      value={selectedTarget}
                      onChange={(e) => setSelectedTarget(e.target.value)}
                    >
                      {Array.from(latestScansByTarget.keys()).map(domain => (
                        <option key={domain} value={domain}>{domain}</option>
                      ))}
                    </select>
                  </div>
                  {targetModes.size > 1 && (
                    <div className="flex items-center gap-2">
                      <label htmlFor="mode-select" className="text-sm text-slate-400">Scan Depth:</label>
                      <select
                        id="mode-select"
                        className="bg-slate-950 border border-slate-800 text-slate-300 text-sm rounded-lg focus:ring-indigo-500 focus:border-indigo-500 p-2"
                        value={selectedMode}
                        onChange={(e) => setSelectedMode(e.target.value)}
                      >
                        <option value="active">Advanced</option>
                        <option value="passive">Basic</option>
                      </select>
                    </div>
                  )}
                </div>
              </div>
              <div className="h-72 w-full">
                {trendData.length > 1 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={trendData}>
                      <defs>
                        <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#6366f1" stopOpacity={0.4}/>
                          <stop offset="95%" stopColor="#6366f1" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                      <XAxis
                        dataKey="timestamp"
                        padding={{ left: 25, right: 25 }}
                        stroke="#64748b"
                        tick={{ fontSize: 11, fill: '#64748b' }}
                        minTickGap={40}
                      />
                      <YAxis domain={[0, 100]} stroke="#64748b" />
                      <Tooltip content={<CustomTooltip />} />
                      <Area
                        type="linear"
                        dataKey="score"
                        stroke="#818cf8"
                        strokeWidth={3}
                        fillOpacity={1}
                        fill="url(#scoreGrad)"
                        activeDot={{ r: 6, fill: '#6366f1', strokeWidth: 2, stroke: '#0f172a' }}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : trendData.length === 1 ? (
                  <div className="h-full flex flex-col items-center justify-center text-slate-400">
                    <p className="text-4xl font-bold text-indigo-400 mb-2">{trendData[0].score}/100</p>
                    <p className="text-sm">Single scan recorded for this target & depth.</p>
                    <p className="text-xs text-slate-500">Run another scan to generate a trend.</p>
                  </div>
                ) : (
                  <div className="h-full flex flex-col items-center justify-center text-slate-500">
                    <p>No historical scans found for this target & depth.</p>
                  </div>
                )}
              </div>
            </div>

            {/* Findings Overview */}
            <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex flex-col">
              <h2 className="text-lg font-semibold text-slate-50 mb-6">Findings Overview</h2>
              <div className="space-y-4 flex-1 justify-center flex flex-col">
                {totalCritical > 0 && (
                  <div className="flex justify-between items-center">
                    <span className="text-sm font-medium text-rose-500 flex items-center gap-2"><AlertCircle size={16}/> Critical</span>
                    <span className="text-lg font-bold text-slate-300">{totalCritical}</span>
                  </div>
                )}
                <div className="flex justify-between items-center">
                  <span className="text-sm font-medium text-rose-400 flex items-center gap-2"><AlertTriangle size={16}/> High</span>
                  <span className="text-lg font-bold text-slate-300">{totalHigh}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm font-medium text-amber-400 flex items-center gap-2"><AlertTriangle size={16}/> Medium</span>
                  <span className="text-lg font-bold text-slate-300">{totalMedium}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm font-medium text-blue-400 flex items-center gap-2"><Info size={16}/> Low</span>
                  <span className="text-lg font-bold text-slate-300">{totalLow}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm font-medium text-slate-400 flex items-center gap-2"><CheckCircle2 size={16}/> Info</span>
                  <span className="text-lg font-bold text-slate-300">{totalInfo}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Needs Attention Section */}
          {topAttention.length > 0 && (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
              <div className="p-6 border-b border-slate-800 flex justify-between items-center">
                <h2 className="text-lg font-semibold text-slate-50">Needs Attention</h2>
              </div>
              <div className="divide-y divide-slate-800">
                {topAttention.map((finding, idx) => (
                  <div key={idx} className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 hover:bg-slate-900/50 transition-colors">
                    <div>
                      <p className="text-sm text-slate-400 font-medium mb-1">{finding.target}</p>
                      <p className="text-slate-50 font-medium">{finding.name}</p>
                    </div>
                    <div className="flex flex-wrap sm:flex-nowrap items-center gap-4">
                      <div className="flex items-center gap-3">
                        <span className={`text-xs font-bold uppercase ${getSeverityColor(finding.severity)}`}>
                          {finding.severity}
                        </span>
                        {finding.cvss_score !== null && finding.cvss_score !== undefined ? (
                          <span className="text-xs text-slate-400 font-mono bg-slate-950 border border-slate-800 px-2 py-1 rounded">
                            {finding.cvss?.startsWith('CVSS:4') ? 'CVSS 4.0' : (finding.cvss?.startsWith('CVSS:3') ? 'CVSS 3.1' : 'CVSS')} · {finding.cvss_score}
                          </span>
                        ) : (
                          <span className="text-xs text-slate-500 font-mono bg-slate-950 border border-slate-800 px-2 py-1 rounded">CVSS N/A</span>
                        )}
                      </div>
                      <Link
                        to={`/history/${finding.scanId}`}
                        className="text-sm font-medium text-indigo-400 hover:text-indigo-300 flex items-center gap-1 shrink-0"
                      >
                        View Report <ChevronRight size={16} />
                      </Link>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recent Scans List */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
            <div className="flex items-center justify-between p-6 border-b border-slate-800">
              <h2 className="text-lg font-semibold text-slate-50">Recent Scans</h2>
              <Link className="text-xs font-mono text-indigo-400 hover:text-indigo-300 flex items-center gap-1 transition-colors" to="/history">
                View Scan History <ChevronRight size={14} />
              </Link>
            </div>

            {scans.length > 0 ? (
              <div className="p-4 space-y-3">
                {scans.slice(0, 5).map((scan) => {
                  const cleanDomain = getDomain(scan.target_url);
                  const d = new Date(scan.created_at);
                  const formattedDate = formatDateCompact(d);

                  // Extract actual mode
                  const modeStr = scan.report_data?.scan_mode;
                  const scanMode = modeStr === 'active' ? 'Advanced' : 'Basic';

                  // Compute actual severity counts fallback safely
                  const hasSeverityCounts = scan.report_data?.severity_counts;
                  const hasFindings = scan.report_data?.findings && Array.isArray(scan.report_data.findings);

                  let crit = 0, high = 0, med = 0, low = 0;
                  let breakdownAvailable = false;

                  if (hasSeverityCounts) {
                    crit = scan.report_data.severity_counts.Critical || 0;
                    high = scan.report_data.severity_counts.High || 0;
                    med = scan.report_data.severity_counts.Medium || 0;
                    low = scan.report_data.severity_counts.Low || 0;
                    breakdownAvailable = true;
                  } else if (hasFindings) {
                    scan.report_data.findings.forEach(f => {
                      if (f.severity === 'Critical') crit++;
                      else if (f.severity === 'High') high++;
                      else if (f.severity === 'Medium') med++;
                      else if (f.severity === 'Low') low++;
                    });
                    breakdownAvailable = true;
                  }

                  return (
                    <div
                      key={scan.id}
                      onClick={() => navigate(`/history/${scan.id}`)}
                      className="group flex flex-col md:flex-row md:items-center justify-between p-4 rounded-xl border border-slate-800/80 bg-slate-900/50 hover:bg-slate-900/90 hover:border-indigo-500/40 transition-all cursor-pointer gap-4"
                      title={scan.target_url}
                    >
                      <div className="flex items-center">
                        <img
                          src={`https://www.google.com/s2/favicons?domain=${cleanDomain}&sz=32`}
                          className="w-8 h-8 rounded-md mr-4 opacity-80 group-hover:opacity-100 transition-opacity bg-white/10"
                          alt=""
                        />
                        <div className="flex flex-col">
                          <span className="text-slate-50 font-medium truncate max-w-xs sm:max-w-md">{cleanDomain}</span>
                          <span className="text-xs text-slate-500 mt-1 capitalize">{scanMode} · {formattedDate}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-4 justify-between md:justify-end w-full md:w-auto">
                        <div className="flex items-center gap-3">
                          <span className={`px-2.5 py-1 rounded-md text-xs font-bold border shrink-0 ${
                            scan.score >= 80 ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
                            scan.score >= 50 ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' :
                            'bg-rose-500/10 text-rose-400 border-rose-500/20'
                          }`}>
                            {scan.score}/100
                          </span>
                          {breakdownAvailable ? (
                            <span className="text-xs font-medium text-slate-400 hidden sm:block">
                              {crit > 0 && `${crit} Critical · `}{high} High · {med} Medium · {low} Low
                            </span>
                          ) : (
                            <span className="text-xs font-medium text-slate-400 hidden sm:block">
                              Severity breakdown unavailable
                            </span>
                          )}
                        </div>

                        <span className="text-xs font-medium text-slate-400 group-hover:text-indigo-400 flex items-center gap-1 transition-colors shrink-0">
                          View Report <ChevronRight className="w-4 h-4 transition-transform group-hover:translate-x-1" />
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="p-6 text-center text-slate-500">
                You haven't run any scans yet.
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
};

export default Dashboard;
