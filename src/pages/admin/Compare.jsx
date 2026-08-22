import React, { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Loader2, TrendingUp, TrendingDown, Plus, Minus, Equal } from 'lucide-react';
import { adminApi } from '../../lib/api/admin';


const safeRender = (val) => {
  if (val === null || val === undefined) return 'None';
  if (typeof val === 'string' || typeof val === 'number' || typeof val === 'boolean') return String(val);
  if (Array.isArray(val)) return val.map(v => safeRender(v)).join(', ');
  if (typeof val === 'object') {
    if (val.raw) return String(val.raw);
    return JSON.stringify(val);
  }
  return 'Unknown';
};

const FindingCard = ({ item, type }) => {

  const isImproved = type === 'improved';
  const isRegressed = type === 'regressed';
  const isAdded = type === 'added';
  const isRemoved = type === 'removed';
  const isUnchanged = type === 'unchanged';

  const f = isImproved || isRegressed ? item.new : item;

  return (
    <div className={`p-4 rounded border ${
      isImproved ? 'bg-green-500/10 border-green-500/30' :
      isRegressed ? 'bg-red-500/10 border-red-500/30' :
      isAdded ? 'bg-orange-500/10 border-orange-500/30' :
      isRemoved ? 'bg-slate-500/10 border-slate-500/30 opacity-75' :
      'bg-slate-800/50 border-slate-700'
    }`}>
      <div className="flex justify-between items-start mb-2">
        <h4 className="font-medium">{f.name}</h4>
        {(isImproved || isRegressed) && (
          <div className="flex items-center gap-2 text-xs font-mono bg-slate-900 px-2 py-1 rounded">
            <span className="text-slate-400">{item.old.severity}</span>
            <span className="text-slate-500">→</span>
            <span className={isImproved ? 'text-green-400' : 'text-red-400'}>{item.new.severity}</span>
          </div>
        )}
        {(isAdded || isRemoved || isUnchanged) && (
          <span className="text-xs font-mono bg-slate-900 px-2 py-1 rounded text-slate-300">
            {f.severity}
          </span>
        )}
      </div>
      {(isImproved || isRegressed) && (
        <div className="text-sm text-slate-400 space-y-2 mt-3 pt-3 border-t border-slate-800/50">
          <div><span className="text-slate-500 text-xs uppercase block mb-1">Old Evidence</span><span className="font-mono text-xs">{safeRender(item.old.evidence)}</span></div>
          <div><span className="text-slate-500 text-xs uppercase block mb-1">New Evidence</span><span className="font-mono text-xs">{safeRender(item.new.evidence)}</span></div>
        </div>
      )}
      {(isAdded || isRemoved || isUnchanged) && f.evidence && (
        <div className="text-sm text-slate-400 mt-2 font-mono text-xs">
          {safeRender(f.evidence)}
        </div>
      )}
    </div>
  );
};

export default function Compare() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const scan1 = searchParams.get('scan1');
  const scan2 = searchParams.get('scan2');

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!scan1 || !scan2) {
      setError('Missing scan IDs. Please select two scans from the Scans page.');
      setLoading(false);
      return;
    }

    const fetchComparison = async () => {
      try {
        const res = await adminApi.compareScans(scan1, scan2);
        setData(res);
      } catch (err) {
        setError(err.message || 'Failed to load comparison.');
      } finally {
        setLoading(false);
      }
    };

    fetchComparison();
  }, [scan1, scan2]);

  if (loading) {
    return (
      <div className="flex justify-center p-8">
        <Loader2 className="w-8 h-8 text-indigo-500 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl mx-auto pb-12">
      <div className="flex items-center gap-4">
        <button 
          onClick={() => navigate('/admin/scans')}
          className="p-2 hover:bg-slate-800 rounded-lg transition-colors text-slate-400 hover:text-white"
        >
          <ArrowLeft className="w-5 h-5" />
        </button>
        <h1 className="text-2xl font-bold">Compare Scans</h1>
      </div>

      {error ? (
        <div className="p-4 bg-red-500/10 border border-red-500/50 rounded text-red-400">
          {error}
        </div>
      ) : data ? (
        <div className="space-y-8">
          {/* Summary Section */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 bg-slate-900 border border-slate-800 rounded-xl p-6">
            <div className="space-y-4">
              <div>
                <h3 className="text-sm font-medium text-slate-400 mb-1">Target</h3>
                <p className="font-mono">{data.target_url}</p>
              </div>
              <div>
                <h3 className="text-sm font-medium text-slate-400 mb-1">Scan Type</h3>
                <p>{data.scan_mode}</p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">Older Scan</h3>
                  <p className="text-sm">{data.old_date ? new Date(data.old_date).toLocaleString() : 'Unknown'}</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-1">Newer Scan</h3>
                  <p className="text-sm">{data.new_date ? new Date(data.new_date).toLocaleString() : 'Unknown'}</p>
                </div>
              </div>
            </div>
            <div className="flex items-center justify-center bg-slate-950 rounded-lg border border-slate-800 p-6">
              <div className="text-center space-y-2">
                <h3 className="text-sm font-medium text-slate-400">Score Change</h3>
                <div className="flex items-baseline justify-center gap-4">
                  <span className="text-2xl text-slate-500 line-through">{data.old_score}</span>
                  <span className="text-4xl font-bold">{data.new_score}</span>
                </div>
                <div className={`text-sm font-medium ${data.score_change > 0 ? 'text-green-400' : data.score_change < 0 ? 'text-red-400' : 'text-slate-400'}`}>
                  {data.score_change > 0 ? '+' : ''}{data.score_change} points
                </div>
              </div>
            </div>
          </div>

          {/* Sections */}
          <div className="space-y-6">
            <section>
              <h2 className="text-lg font-bold mb-4 flex items-center gap-2 text-green-400">
                <TrendingUp className="w-5 h-5" /> Improved ({data.improved.length})
              </h2>
              {data.improved.length === 0 ? (
                <p className="text-slate-500 italic p-4 bg-slate-900 rounded border border-slate-800 text-center">None</p>
              ) : (
                <div className="grid gap-4">
                  {data.improved.map((item, i) => <FindingCard key={i} item={item} type="improved" />)}
                </div>
              )}
            </section>

            <section>
              <h2 className="text-lg font-bold mb-4 flex items-center gap-2 text-red-400">
                <TrendingDown className="w-5 h-5" /> Regressed ({data.regressed.length})
              </h2>
              {data.regressed.length === 0 ? (
                <p className="text-slate-500 italic p-4 bg-slate-900 rounded border border-slate-800 text-center">None</p>
              ) : (
                <div className="grid gap-4">
                  {data.regressed.map((item, i) => <FindingCard key={i} item={item} type="regressed" />)}
                </div>
              )}
            </section>

            <section>
              <h2 className="text-lg font-bold mb-4 flex items-center gap-2 text-orange-400">
                <Plus className="w-5 h-5" /> Added ({data.added.length})
              </h2>
              {data.added.length === 0 ? (
                <p className="text-slate-500 italic p-4 bg-slate-900 rounded border border-slate-800 text-center">None</p>
              ) : (
                <div className="grid gap-4">
                  {data.added.map((item, i) => <FindingCard key={i} item={item} type="added" />)}
                </div>
              )}
            </section>

            <section>
              <h2 className="text-lg font-bold mb-4 flex items-center gap-2 text-slate-400">
                <Minus className="w-5 h-5" /> Removed ({data.removed.length})
              </h2>
              {data.removed.length === 0 ? (
                <p className="text-slate-500 italic p-4 bg-slate-900 rounded border border-slate-800 text-center">None</p>
              ) : (
                <div className="grid gap-4">
                  {data.removed.map((item, i) => <FindingCard key={i} item={item} type="removed" />)}
                </div>
              )}
            </section>

            <section>
              <h2 className="text-lg font-bold mb-4 flex items-center gap-2 text-slate-500">
                <Equal className="w-5 h-5" /> Unchanged ({data.unchanged.length})
              </h2>
              {data.unchanged.length === 0 ? (
                <p className="text-slate-500 italic p-4 bg-slate-900 rounded border border-slate-800 text-center">None</p>
              ) : (
                <div className="grid gap-4">
                  {data.unchanged.map((item, i) => <FindingCard key={i} item={item} type="unchanged" />)}
                </div>
              )}
            </section>
          </div>
        </div>
      ) : null}
    </div>
  );
}
