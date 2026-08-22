import React, { useEffect, useState } from 'react';
import { Navigate, Outlet, Link, useLocation } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { adminApi } from '../../lib/api/admin';
import { ShieldAlert, Users, Activity, List, LayoutDashboard, Loader2, ArrowLeft } from 'lucide-react';

export default function AdminLayout() {
  const { session, loading: authLoading } = useAuth();
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [authorizing, setAuthorizing] = useState(true);
  const [error, setError] = useState(null);
  const location = useLocation();

  useEffect(() => {
    if (authLoading) return;
    
    if (!session) {
      setAuthorizing(false);
      return;
    }

    const checkAuth = async () => {
      try {
        const data = await adminApi.getMe();
        if (data.role === 'admin') {
          setIsAuthorized(true);
        } else {
          setIsAuthorized(false);
          setError('Admin privileges required.');
        }
      } catch (err) {
        setIsAuthorized(false);
        setError(err.message || 'Access Denied');
      } finally {
        setAuthorizing(false);
      }
    };
    
    checkAuth();
  }, [session, authLoading]);

  if (authLoading || authorizing) {
    return (
      <div className="flex-1 flex items-center justify-center bg-slate-950">
        <Loader2 className="w-8 h-8 text-indigo-500 animate-spin" />
      </div>
    );
  }

  if (!session) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  if (!isAuthorized) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center bg-slate-950 text-slate-50 p-6 text-center">
        <ShieldAlert className="w-16 h-16 text-red-500 mb-4" />
        <h1 className="text-2xl font-bold mb-2">Access Denied</h1>
        <p className="text-slate-400 mb-6 max-w-md">You do not have permission to access this area.</p>
        <Link to="/" className="px-6 py-2 bg-indigo-600 hover:bg-indigo-500 rounded font-medium transition-colors">
          Return to Scanner
        </Link>
      </div>
    );
  }

  const navItems = [
    { name: 'Overview', path: '/admin', icon: LayoutDashboard },
    { name: 'Users', path: '/admin/users', icon: Users },
    { name: 'Scans', path: '/admin/scans', icon: Activity },
    { name: 'Audit Logs', path: '/admin/audit-logs', icon: List }
  ];

  return (
    <div className="flex-1 flex flex-col md:flex-row bg-slate-950 text-slate-50 min-h-screen">
      <aside className="w-full md:w-64 bg-slate-900 border-r border-slate-800 flex-shrink-0 flex flex-col">
        <div className="p-4 border-b border-slate-800">
          <h2 className="text-lg font-bold flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-indigo-500" />
            Admin Dashboard
          </h2>
        </div>
        <nav className="p-4 flex flex-row md:flex-col gap-2 overflow-x-auto md:overflow-visible flex-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path || (item.path !== '/admin' && location.pathname.startsWith(item.path));
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`flex items-center gap-3 px-3 py-2 rounded whitespace-nowrap transition-colors ${
                  isActive ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                }`}
              >
                <Icon className="w-4 h-4 flex-shrink-0" />
                <span className="font-medium text-sm">{item.name}</span>
              </Link>
            );
          })}
        </nav>
        <div className="p-4 border-t border-slate-800 hidden md:block mt-auto">
          <Link to="/" className="flex items-center gap-3 px-3 py-2 rounded text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition-colors">
            <ArrowLeft className="w-4 h-4 flex-shrink-0" />
            <span className="font-medium text-sm">Exit Admin</span>
          </Link>
        </div>
        <div className="p-2 md:hidden">
          <Link to="/" className="flex items-center gap-2 px-3 py-2 rounded text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition-colors justify-center">
            <ArrowLeft className="w-4 h-4 flex-shrink-0" />
            <span className="font-medium text-sm">Exit Admin</span>
          </Link>
        </div>
      </aside>
      <main className="flex-1 overflow-x-hidden p-4 md:p-8 bg-slate-950">
        <Outlet />
      </main>
    </div>
  );
}
