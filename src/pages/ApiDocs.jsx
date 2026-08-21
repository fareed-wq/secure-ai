import React, { useEffect } from 'react';
import { Code, Clock, Terminal, Key, Search, FileJson, AlertCircle, Zap, Code2 } from 'lucide-react';

const ApiDocs = () => {
  useEffect(() => {
    document.title = "API Documentation | URLScannerOnline";
  }, []);

  const plannedSections = [
    { label: "API Overview", icon: <Terminal size={18} /> },
    { label: "Authentication", icon: <Key size={18} /> },
    { label: "Scan Endpoints", icon: <Search size={18} /> },
    { label: "Scan Results", icon: <FileJson size={18} /> },
    { label: "Error Handling", icon: <AlertCircle size={18} /> },
    { label: "Rate Limits", icon: <Zap size={18} /> },
    { label: "Code Examples", icon: <Code2 size={18} /> },
  ];

  return (
    <div className="space-y-16 pb-12">
      {/* Hero */}
      <section className="relative overflow-hidden rounded-3xl bg-slate-900 border border-slate-800 p-8 md:p-16 text-center">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-full max-w-4xl opacity-30 pointer-events-none">
          <div className="absolute inset-0 bg-gradient-to-r from-indigo-500/20 via-purple-500/20 to-blue-500/20 blur-3xl rounded-full transform -translate-y-1/2" />
        </div>
        <div className="relative z-10 max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 text-indigo-400 text-sm font-semibold mb-6">
            <Code className="w-4 h-4" />
            Developers
          </div>
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-black text-slate-50 mb-6 tracking-tight">
            API Documentation
          </h1>
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400 font-medium mb-6">
            <Clock className="w-5 h-5" />
            Coming Soon
          </div>
          <p className="text-lg md:text-xl text-slate-400 leading-relaxed max-w-2xl mx-auto">
            API access is currently under development. We are working on a stable API that will allow developers to integrate URLScannerOnline security scanning into their own applications and workflows.
          </p>
        </div>
      </section>

      {/* Planned Documentation */}
      <section className="max-w-4xl mx-auto px-4 md:px-0">
        <div className="rounded-3xl border border-slate-800 bg-slate-900 p-8 md:p-12">
          <div className="text-center mb-8">
            <h2 className="text-2xl font-bold text-slate-50 mb-4">Planned Documentation</h2>
            <p className="text-slate-400">
              Detailed documentation will be published when the API is ready for public use.
            </p>
          </div>
          
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
            {plannedSections.map((item, idx) => (
              <div 
                key={idx} 
                className="flex items-center gap-3 p-4 rounded-xl border border-slate-800 bg-slate-950 text-slate-300 select-none"
              >
                <div className="text-indigo-400 shrink-0">
                  {item.icon}
                </div>
                <span className="font-medium">{item.label}</span>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
};

export default ApiDocs;
