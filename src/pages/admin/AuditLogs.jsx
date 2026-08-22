import React, { useEffect, useState } from 'react';
import { adminApi } from '../../lib/api/admin';
import { Loader2, ChevronDown, ChevronRight } from 'lucide-react';

const ExpandableRow = ({ log }) => {
  const [expanded, setExpanded] = useState(false);
  const date = new Date(log.created_at);
  const hasDetails = log.before_state || log.after_state || log.reason;

  return (
    <React.Fragment>
      <tr className="hover:bg-slate-800/50 cursor-pointer" onClick={() => hasDetails && setExpanded(!expanded)}>
        <td className="px-4 py-3">{date.toLocaleDateString()}</td>
        <td className="px-4 py-3 text-slate-400">{date.toLocaleTimeString()}</td>
        <td className="px-4 py-3 font-mono text-xs truncate max-w-[120px]" title={log.admin_user_id}>{log.admin_user_id}</td>
        <td className="px-4 py-3 font-medium text-indigo-400">{log.action}</td>
        <td className="px-4 py-3 capitalize">{log.resource_type}</td>
        <td className="px-4 py-3 font-mono text-xs truncate max-w-[120px]" title={log.resource_id}>{log.resource_id}</td>
        <td className="px-4 py-3 w-8">
          {hasDetails && (
            expanded ? <ChevronDown className="w-4 h-4 text-slate-400" /> : <ChevronRight className="w-4 h-4 text-slate-400" />
          )}
        </td>
      </tr>
      {expanded && hasDetails && (
        <tr className="bg-slate-900/50">
          <td colSpan="7" className="px-4 py-3 border-t border-slate-800/50 text-xs">
            {log.reason && <div className="mb-2"><span className="text-slate-400">Reason:</span> {log.reason}</div>}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {log.before_state && (
                <div>
                  <div className="text-slate-400 mb-1">Before State:</div>
                  <pre className="bg-slate-950 p-2 rounded border border-slate-800 overflow-x-auto text-slate-300">
                    {JSON.stringify(log.before_state, null, 2)}
                  </pre>
                </div>
              )}
              {log.after_state && (
                <div>
                  <div className="text-slate-400 mb-1">After State:</div>
                  <pre className="bg-slate-950 p-2 rounded border border-slate-800 overflow-x-auto text-slate-300">
                    {JSON.stringify(log.after_state, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </React.Fragment>
  );
};

export default function AuditLogs() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const data = await adminApi.getAuditLogs(50, 0);
        setLogs(Array.isArray(data) ? data : []);
      } catch (err) {
        setError(err.message || 'Failed to load audit logs');
      } finally {
        setLoading(false);
      }
    };
    fetchLogs();
  }, []);

  if (loading) {
    return <div className="flex justify-center p-8"><Loader2 className="w-8 h-8 text-indigo-500 animate-spin" /></div>;
  }

  if (error) {
    return <div className="p-4 bg-red-500/10 border border-red-500/50 rounded text-red-400">{error}</div>;
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Audit Logs</h1>
      
      {logs.length === 0 ? (
        <div className="p-8 text-center text-slate-400 border border-slate-800 rounded bg-slate-900">
          No audit logs found.
        </div>
      ) : (
        <div className="overflow-x-auto rounded border border-slate-800">
          <table className="w-full text-left text-sm whitespace-nowrap">
            <thead className="bg-slate-900 border-b border-slate-800 text-slate-400">
              <tr>
                <th className="px-4 py-3 font-medium">DATE</th>
                <th className="px-4 py-3 font-medium">TIME</th>
                <th className="px-4 py-3 font-medium">ADMIN</th>
                <th className="px-4 py-3 font-medium">ACTION</th>
                <th className="px-4 py-3 font-medium">RESOURCE</th>
                <th className="px-4 py-3 font-medium">RESOURCE ID</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {logs.map(log => <ExpandableRow key={log.id} log={log} />)}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
