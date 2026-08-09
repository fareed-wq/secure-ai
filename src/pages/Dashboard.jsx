import React, { useState, useEffect } from 'react';
import { ShieldCheck, Activity, Target, AlertTriangle, Loader2 } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { useAuth } from "../contexts/AuthContext";
import { supabase } from '../lib/supabase';

const Dashboard = () => {
  const { user } = useAuth();
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
  
  // Trend Data (last 7 scans in chronological order)
  const trendData = [...scans]
    .slice(0, 7)
    .reverse()
    .map((scan) => {
      const d = new Date(scan.created_at);
      return {
        name: d.toLocaleDateString('en-US', { weekday: 'short' }),
        score: scan.score,
        fullDate: d.toLocaleDateString()
      };
    });
    
  if (trendData.length === 0) {
    trendData.push({ name: 'Mon', score: 0 }); // Fallback empty state
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-white tracking-tight">Overview</h1>
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
                <p className="text-3xl font-bold text-red-400 mt-2">0</p>
              </div>
              <div className="p-3 bg-red-500/10 rounded-lg"><AlertTriangle className="w-6 h-6 text-red-500" /></div>
            </div>
          </div>

          {/* Charts Section */}
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl">
            <h2 className="text-lg font-semibold text-white mb-6">Security Score Trend</h2>
            <div className="h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trendData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="name" stroke="#64748b" />
                  <YAxis domain={[0, 100]} stroke="#64748b" />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#f8fafc' }}
                    itemStyle={{ color: '#818cf8' }}
                  />
                  <Line 
                    type="monotone" 
                    dataKey="score" 
                    stroke="#6366f1" 
                    strokeWidth={3}
                    dot={{ r: 4, fill: '#6366f1', strokeWidth: 2, stroke: '#0f172a' }} 
                    activeDot={{ r: 6 }} 
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Recent Scans Stub */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
            <div className="p-6 border-b border-slate-800">
              <h2 className="text-lg font-semibold text-white">Recent Scans</h2>
            </div>
            
            {scans.length > 0 ? (
              <div className="divide-y divide-slate-800/50">
                {scans.slice(0, 5).map((scan) => (
                  <div key={scan.id} className="p-4 flex items-center justify-between hover:bg-slate-800/30 transition-colors">
                    <div className="flex flex-col">
                      <span className="text-white font-medium">{scan.target_url}</span>
                      <span className="text-xs text-slate-500">{new Date(scan.created_at).toLocaleString()}</span>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className={`px-2 py-1 rounded text-xs font-bold ${
                        scan.score >= 80 ? 'bg-emerald-500/10 text-emerald-400' :
                        scan.score >= 50 ? 'bg-amber-500/10 text-amber-400' :
                        'bg-red-500/10 text-red-400'
                      }`}>
                        {scan.score}/100
                      </span>
                    </div>
                  </div>
                ))}
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
