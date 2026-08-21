import React, { useState, useEffect } from 'react';
import { ShieldCheck, Activity, Target, AlertTriangle, Loader2, CheckCircle2, ChevronRight } from 'lucide-react';
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
        <p className="text-slate-400 text-xs mb-2">{data.date} at {label}</p>
        <p className="text-indigo-400 font-bold">Score: {data.score}/100</p>
      </div>
    );
  }
  return null;
};

const Dashboard = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

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
  const avgScore = totalScans > 0 
    ? Math.round(scans.reduce((acc, curr) => acc + curr.score, 0) / totalScans) 
    : '--';
  
  const activeTargets = new Set(scans.map(s => s.target_url)).size;
  
  const criticalIssues = scans.reduce((acc, scan) => {
    const findings = scan.report_data?.findings || [];
    return acc + findings.filter(f => f.severity === 'Critical').length;
  }, 0);
  
  // Trend Data (last 7 scans in chronological order)
  const trendData = [...scans]
    .slice(0, 7)
    .reverse()
    .map((scan) => {
      const d = new Date(scan.created_at);
      let domain = scan.target_url;
      try {
        domain = new URL(scan.target_url).hostname.replace('www.', '');
      } catch(e) {}
      
      return {
        timestamp: d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        date: d.toLocaleDateString(),
        score: scan.score,
        domain
      };
    });
    
  if (trendData.length === 0) {
    trendData.push({ timestamp: '12:00 AM', date: new Date().toLocaleDateString(), score: 0, domain: 'No Data' });
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-slate-50 tracking-tight">Overview</h1>
          <p className="text-slate-400 mt-1">Welcome back, {user?.user_metadata?.full_name || user?.email || 'Demo User'}</p>
        </div>
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
                <p className="text-sm font-medium text-slate-400 uppercase tracking-wider">Avg Security Score</p>
                <p className="text-3xl font-bold text-emerald-400 mt-2">{avgScore}{avgScore !== '--' ? '/100' : ''}</p>
              </div>
              <div className="p-3 bg-emerald-500/10 rounded-lg"><ShieldCheck className="w-6 h-6 text-emerald-500" /></div>
            </div>

            <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex items-start justify-between">
              <div>
                <p className="text-sm font-medium text-slate-400 uppercase tracking-wider">Total Scans</p>
                <p className="text-3xl font-bold text-indigo-400 mt-2">{totalScans}</p>
              </div>
              <div className="p-3 bg-indigo-500/10 rounded-lg"><Activity className="w-6 h-6 text-indigo-500" /></div>
            </div>

            <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex items-start justify-between">
              <div>
                <p className="text-sm font-medium text-slate-400 uppercase tracking-wider">Active Targets</p>
                <p className="text-3xl font-bold text-blue-400 mt-2">{activeTargets}</p>
              </div>
              <div className="p-3 bg-blue-500/10 rounded-lg"><Target className="w-6 h-6 text-blue-500" /></div>
            </div>

            <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex items-start justify-between">
              <div>
                <p className="text-sm font-medium text-slate-400 uppercase tracking-wider">Critical Issues</p>
                <p className={`text-3xl font-bold mt-2 ${criticalIssues === 0 ? 'text-emerald-400' : 'text-rose-400'}`}>
                  {criticalIssues}
                </p>
              </div>
              <div className={`p-3 rounded-lg border ${
                criticalIssues === 0 
                ? 'bg-emerald-500/10 border-emerald-500/20' 
                : 'bg-rose-500/10 border-rose-500/20'
              }`}>
                {criticalIssues === 0 ? (
                  <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                ) : (
                  <AlertTriangle className="w-6 h-6 text-rose-400" />
                )}
              </div>
            </div>
          </div>

          {/* Charts Section */}
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl">
            <h2 className="text-lg font-semibold text-slate-50 mb-6">Security Score Trend</h2>
            <div className="h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData}>
                  <defs>
                    <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#6366f1" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#6366f1" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="timestamp" padding={{ left: 25, right: 25 }} stroke="#64748b" tick={{ fontSize: 11, fill: '#64748b' }} />
                  <YAxis domain={[0, 100]} stroke="#64748b" />
                  <Tooltip content={<CustomTooltip />} />
                  <Area 
                    type="monotone" 
                    dataKey="score" 
                    stroke="#818cf8" 
                    strokeWidth={3} 
                    fillOpacity={1} 
                    fill="url(#scoreGrad)" 
                    activeDot={{ r: 6, fill: '#6366f1', strokeWidth: 2, stroke: '#0f172a' }}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Recent Scans List */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
            <div className="flex items-center justify-between p-6 border-b border-slate-800">
              <h2 className="text-lg font-semibold text-slate-50">Recent Scans</h2>
              <Link className="text-xs font-mono text-indigo-400 hover:text-indigo-300 flex items-center gap-1 transition-colors" to="/history">
                View Scan History →
              </Link>
            </div>
            
            {scans.length > 0 ? (
              <div className="p-4 space-y-3">
                {scans.slice(0, 5).map((scan) => {
                  let cleanDomain = scan.target_url;
                  try {
                    cleanDomain = new URL(scan.target_url).hostname.replace('www.', '');
                  } catch(e) {}

                  return (
                    <div 
                      key={scan.id} 
                      onClick={() => navigate('/history')}
                      className="group flex items-center justify-between p-4 rounded-xl border border-slate-800/80 bg-slate-900/50 hover:bg-slate-900/90 hover:border-indigo-500/40 transition-all cursor-pointer"
                    >
                      <div className="flex items-center">
                        <img 
                          src={`https://www.google.com/s2/favicons?domain=${cleanDomain}&sz=32`} 
                          className="w-8 h-8 rounded-md mr-4 opacity-80 group-hover:opacity-100 transition-opacity bg-white/10" 
                          alt="" 
                        />
                        <div className="flex flex-col">
                          <span className="text-slate-50 font-medium">{scan.target_url}</span>
                          <span className="text-xs text-slate-500 mt-1">{new Date(scan.created_at).toLocaleString()}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-6">
                        <span className={`px-2.5 py-1 rounded-md text-xs font-bold border ${
                          scan.score >= 80 ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
                          scan.score >= 50 ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' :
                          'bg-rose-500/10 text-rose-400 border-rose-500/20'
                        }`}>
                          {scan.score}/100
                        </span>
                        
                        <span className="text-xs font-medium text-slate-400 group-hover:text-indigo-400 flex items-center gap-1 transition-colors"> 
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
