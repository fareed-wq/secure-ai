import React from 'react';
import { History, ExternalLink, Calendar } from 'lucide-react';
import { Link } from 'react-router-dom';

const mockHistory = [
  { id: '1', target: 'example.com', score: 85, grade: 'B', date: '2026-08-04T10:00:00Z', status: 'Completed' },
  { id: '2', target: 'api.demo.com', score: 92, grade: 'A', date: '2026-08-03T15:30:00Z', status: 'Completed' },
  { id: '3', target: 'staging.test.io', score: 65, grade: 'D', date: '2026-08-02T09:15:00Z', status: 'Completed' },
];

const ScanHistory = () => {
  return (
    <div className="space-y-6 text-slate-200">
      <div>
        <h1 className="text-3xl font-bold text-slate-50 tracking-tight">Scan History</h1>
        <p className="text-slate-400 mt-1">Review all your previous security assessments.</p>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-800/50 border-b border-slate-700 text-slate-400 uppercase tracking-wider">
              <tr>
                <th className="p-4 font-medium">Target URL</th>
                <th className="p-4 font-medium">Date</th>
                <th className="p-4 font-medium">Score</th>
                <th className="p-4 font-medium">Status</th>
                <th className="p-4 font-medium text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {mockHistory.map((scan) => (
                <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="p-4 font-medium text-slate-50 flex items-center gap-2">
                    {scan.target}
                  </td>
                  <td className="p-4 text-slate-400 flex items-center gap-2">
                    <Calendar className="w-4 h-4" />
                    {new Date(scan.date).toLocaleDateString()}
                  </td>
                  <td className="p-4">
                    <div className={`inline-flex px-2 py-1 rounded text-xs font-bold ${scan.score >= 85 ? 'bg-emerald-500/10 text-emerald-400' : 'bg-amber-500/10 text-amber-400'}`}>
                      {scan.grade} ({scan.score})
                    </div>
                  </td>
                  <td className="p-4 text-slate-400">{scan.status}</td>
                  <td className="p-4 text-right">
                    <Link to={`/scan?url=${scan.target}`} className="inline-flex items-center gap-1 text-indigo-400 hover:text-indigo-300">
                      View Report <ExternalLink className="w-4 h-4" />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default ScanHistory;
