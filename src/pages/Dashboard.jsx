import React from 'react';
import { ShieldCheck, Activity, Target, AlertTriangle } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { useAuth } from "../contexts/AuthContext";

// Mock data for the MVP dashboard
const mockTrendData = [
  { name: 'Mon', score: 65 },
  { name: 'Tue', score: 72 },
  { name: 'Wed', score: 68 },
  { name: 'Thu', score: 85 },
  { name: 'Fri', score: 92 },
  { name: 'Sat', score: 90 },
  { name: 'Sun', score: 95 },
];

const Dashboard = () => {
  const { user } = useAuth();

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-white tracking-tight">Overview</h1>
          <p className="text-slate-400 mt-1">Welcome back, {user?.user_metadata?.full_name || user?.email || 'Demo User'}</p>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex items-start justify-between">
          <div>
            <p className="text-sm font-medium text-slate-400 uppercase tracking-wider">Avg Security Score</p>
            <p className="text-3xl font-bold text-emerald-400 mt-2">92/100</p>
          </div>
          <div className="p-3 bg-emerald-500/10 rounded-lg"><ShieldCheck className="w-6 h-6 text-emerald-500" /></div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex items-start justify-between">
          <div>
            <p className="text-sm font-medium text-slate-400 uppercase tracking-wider">Total Scans</p>
            <p className="text-3xl font-bold text-indigo-400 mt-2">1,204</p>
          </div>
          <div className="p-3 bg-indigo-500/10 rounded-lg"><Activity className="w-6 h-6 text-indigo-500" /></div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl flex items-start justify-between">
          <div>
            <p className="text-sm font-medium text-slate-400 uppercase tracking-wider">Active Targets</p>
            <p className="text-3xl font-bold text-blue-400 mt-2">8</p>
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
            <LineChart data={mockTrendData}>
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
        <div className="p-6 text-center text-slate-500">
          Scan history populated after first scan...
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
