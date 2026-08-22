import React from 'react';
import { Navigate, Outlet, Link, useLocation } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { ShieldAlert, Users, Activity, List, LayoutDashboard, Loader2, ArrowLeft } from 'lucide-react';

export default function AdminLayout() {
  const { session, loading: authLoading, isAdmin, isAdminLoading } = useAuth();
  const location = useLocation();

  if (authLoading || isAdminLoading) {
    return (
      <div className="flex-1 flex items-center justify-center bg-slate-950">
        <Loader2 className="w-8 h-8 text-indigo-500 animate-spin" />
      </div>
    );
  }

  if (!session) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  if (!isAdmin) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center bg-slate-950 text-slate-50 p-6 text-center">
        <ShieldAlert className="w-16 h-16 text-red-500 mb-4" />
        <h1 className="text-2xl font-bold mb-2">Access Denied</h1>
        <p className="text-slate-400 mb-6 max-w-md">You do not have permission to access this area.</p>
        <Link
          to="/dashboard"
          className="px-6 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition-colors font-medium flex items-center gap-2"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Dashboard
        </Link>
      </div>
    );
  }

  return (
    <div className="flex-1 flex flex-col bg-slate-950 text-slate-50">
      {/* Top Nav */}
      <header className="border-b border-slate-800 bg-slate-900/50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-8">
            <h1 className="text-xl font-bold text-indigo-400 flex items-center gap-2">
              <ShieldAlert className="w-6 h-6" />
              Admin Control
            </h1>
            <nav className="hidden md:flex items-center gap-1">
              <Link
                to="/admin"
                className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 ${location.pathname === '/admin' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white hover:bg-slate-800/50'}`}
              >
                <LayoutDashboard className="w-4 h-4" />
                Overview
              </Link>
              <Link
                to="/admin/users"
                className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 ${location.pathname.startsWith('/admin/users') ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white hover:bg-slate-800/50'}`}
              >
                <Users className="w-4 h-4" />
                Users
              </Link>
              <Link
                to="/admin/scans"
                className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 ${location.pathname.startsWith('/admin/scans') ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white hover:bg-slate-800/50'}`}
              >
                <Activity className="w-4 h-4" />
                Scans
              </Link>
              <Link
                to="/admin/audit-logs"
                className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 ${location.pathname.startsWith('/admin/audit-logs') ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white hover:bg-slate-800/50'}`}
              >
                <List className="w-4 h-4" />
                Audit Logs
              </Link>
            </nav>
          </div>
          <div>
            <Link to="/dashboard" className="text-sm text-slate-400 hover:text-white transition-colors flex items-center gap-2">
              <ArrowLeft className="w-4 h-4" />
              Exit Admin
            </Link>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        <div className="max-w-7xl mx-auto p-6">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
