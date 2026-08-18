import React, { useState } from 'react';
import { Outlet, Navigate } from 'react-router-dom';
import Sidebar from './Sidebar';
import { useAuth } from '../../contexts/AuthContext';
import { Menu } from 'lucide-react';

const SaaSLayout = () => {
  const { user, isRecovery } = useAuth();
  const [isMobileOpen, setIsMobileOpen] = useState(false);

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  // Lock the user to the reset-password flow if they are in a recovery session
  if (user && isRecovery) {
    return <Navigate to="/reset-password" replace />;
  }

  return (
    <div className="flex h-screen bg-slate-950 text-slate-200 font-sans overflow-hidden">
      <Sidebar isMobileOpen={isMobileOpen} setIsMobileOpen={setIsMobileOpen} />

      <div className="flex-1 flex flex-col h-screen overflow-hidden relative">
        {/* Mobile Header */}
        <div className="md:hidden flex items-center p-4 border-b border-slate-800 bg-slate-950/80 backdrop-blur-md sticky top-0 z-30">
          <button
            onClick={() => setIsMobileOpen(true)}
            className="p-2 -ml-2 text-slate-400 hover:text-slate-50 transition-colors"
          >
            <Menu size={24} />
          </button>
          <span className="ml-2 font-bold text-slate-50 tracking-tight">Dashboard</span>
        </div>

        <div id="main-scroll-container" className="flex-1 overflow-y-auto">
          <main className="p-8 max-w-7xl mx-auto">
            <Outlet />
          </main>
        </div>
      </div>
    </div>
  );
};

export default SaaSLayout;
