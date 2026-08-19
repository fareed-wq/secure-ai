import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import { Menu } from 'lucide-react';

const RootLayout = () => {
  const [isMobileOpen, setIsMobileOpen] = useState(false);

  return (
    <div className="flex h-screen bg-slate-950 text-slate-200 font-sans overflow-hidden">
      <Sidebar isMobileOpen={isMobileOpen} setIsMobileOpen={setIsMobileOpen} />

      <div className="flex-1 flex flex-col h-screen overflow-hidden relative">
        {/* Mobile Header (Hidden on Desktop) */}
        <div className="md:hidden flex items-center p-4 border-b border-slate-800 bg-slate-950/80 backdrop-blur-md sticky top-0 z-30">
          <button
            onClick={() => setIsMobileOpen(true)}
            className="p-2 -ml-2 text-slate-400 hover:text-slate-50 transition-colors"
          >
            <Menu size={24} />
          </button>
          <img src="/logo-transparent.webp" alt="URLScan Online Logo" width="654" height="164" className="ml-2 h-7 w-auto" />
        </div>

        <div id="main-scroll-container" className="flex-1 overflow-y-auto flex flex-col">
          <Outlet />
        </div>
      </div>
    </div>
  );
};

export default RootLayout;
