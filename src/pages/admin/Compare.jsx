import React from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';

export default function Compare() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const scan1 = searchParams.get('scan1');
  const scan2 = searchParams.get('scan2');

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div className="flex items-center gap-4">
        <button 
          onClick={() => navigate('/admin/scans')}
          className="p-2 hover:bg-slate-800 rounded-lg transition-colors text-slate-400 hover:text-white"
        >
          <ArrowLeft className="w-5 h-5" />
        </button>
        <h1 className="text-2xl font-bold">Compare Scans</h1>
      </div>
      
      <div className="p-8 text-center text-slate-400 border border-slate-800 rounded bg-slate-900">
        <h2 className="text-xl font-medium text-white mb-4">Phase 3 placeholder: Compare Engine UI</h2>
        <div className="flex flex-col gap-2 font-mono text-sm">
          <p>Scan 1: {scan1 || 'None'}</p>
          <p>Scan 2: {scan2 || 'None'}</p>
        </div>
      </div>
    </div>
  );
}
