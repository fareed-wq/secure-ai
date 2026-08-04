import React from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';

const RootLayout = () => {
  return (
    <div className="flex h-screen bg-slate-950 text-slate-200 font-sans overflow-hidden">
      <Sidebar />
      <div className="flex-1 overflow-y-auto relative">
        <Outlet />
      </div>
    </div>
  );
};

export default RootLayout;
