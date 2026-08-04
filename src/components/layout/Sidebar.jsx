import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { LayoutDashboard, ShieldCheck, History, Bookmark, FileText, Settings, LogOut, Activity } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';

const Sidebar = () => {
  const location = useLocation();
  const { signOut, user } = useAuth();

  const navItems = [
    { name: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
    { name: 'Run Scan', path: '/scan', icon: Activity },
    { name: 'Scan History', path: '/history', icon: History },
    { name: 'Saved Reports', path: '/reports', icon: Bookmark },
    { name: 'Compare', path: '/compare', icon: FileText },
  ];

  return (
    <div className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col h-screen fixed left-0 top-0 text-slate-300">
      <div className="p-6 flex items-center gap-3">
        <ShieldCheck className="w-8 h-8 text-indigo-500" />
        <span className="text-xl font-bold text-white tracking-tight">Secure-AI</span>
      </div>

      <nav className="flex-1 px-4 space-y-2 mt-4">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = location.pathname === item.path;
          return (
            <Link
              key={item.name}
              to={item.path}
              className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                isActive 
                  ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20' 
                  : 'hover:bg-slate-800/50 hover:text-white'
              }`}
            >
              <Icon className="w-5 h-5" />
              <span className="font-medium text-sm">{item.name}</span>
            </Link>
          );
        })}
      </nav>

      <div className="p-4 border-t border-slate-800 space-y-2">
        <div className="px-4 py-2 mb-2">
          <p className="text-xs text-slate-500 uppercase tracking-wider font-bold mb-1">Account</p>
          <p className="text-sm text-slate-300 truncate">{user?.email || 'Demo User'}</p>
        </div>
        
        <Link
          to="/settings"
          className="flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-slate-800/50 transition-colors"
        >
          <Settings className="w-5 h-5 text-slate-400" />
          <span className="font-medium text-sm">Settings</span>
        </Link>
        <button
          onClick={signOut}
          className="w-full flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-red-500/10 hover:text-red-400 transition-colors"
        >
          <LogOut className="w-5 h-5 text-slate-400" />
          <span className="font-medium text-sm">Sign Out</span>
        </button>
      </div>
    </div>
  );
};

export default Sidebar;
