import React from 'react';
import { Bookmark, FileText, Download } from 'lucide-react';

const mockReports = [
  { id: '1', name: 'Q3 Compliance Audit', target: 'example.com', score: 92, date: '2026-08-01T10:00:00Z' },
  { id: '2', name: 'Pre-Deployment Check', target: 'staging.test.io', score: 85, date: '2026-07-28T14:00:00Z' },
];

const SavedReports = () => {
  return (
    <div className="space-y-6 text-slate-200">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-white tracking-tight">Saved Reports</h1>
          <p className="text-slate-400 mt-1">Bookmarked snapshots for compliance and review.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {mockReports.map((report) => (
          <div key={report.id} className="bg-slate-900 border border-slate-800 rounded-2xl p-6 hover:border-slate-700 transition-colors">
            <div className="flex justify-between items-start mb-4">
              <div className="flex items-center gap-3">
                <div className="p-3 bg-indigo-500/10 rounded-lg">
                  <Bookmark className="w-6 h-6 text-indigo-400" />
                </div>
                <div>
                  <h3 className="font-bold text-lg text-white">{report.name}</h3>
                  <p className="text-sm text-slate-400">{report.target}</p>
                </div>
              </div>
              <div className="text-2xl font-bold text-emerald-400">{report.score}</div>
            </div>
            
            <div className="flex items-center justify-between mt-6 pt-4 border-t border-slate-800">
              <span className="text-xs text-slate-500">Saved on {new Date(report.date).toLocaleDateString()}</span>
              <div className="flex gap-2">
                <button className="p-2 hover:bg-slate-800 rounded-lg text-slate-400 hover:text-white transition-colors" title="View">
                  <FileText className="w-4 h-4" />
                </button>
                <button className="p-2 hover:bg-slate-800 rounded-lg text-slate-400 hover:text-indigo-400 transition-colors" title="Export PDF">
                  <Download className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        ))}
        
        {mockReports.length === 0 && (
          <div className="col-span-2 text-center py-12 text-slate-500 bg-slate-900/50 rounded-2xl border border-slate-800 border-dashed">
            No saved reports yet. Run a scan and bookmark it to save it here.
          </div>
        )}
      </div>
    </div>
  );
};

export default SavedReports;
