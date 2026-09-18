import React, { useEffect, useState } from 'react';

import { useSearchParams, useNavigate } from 'react-router-dom';

import { ArrowLeft, Loader2, TrendingUp, TrendingDown, Plus, Minus, Equal , Layers, Tag, Info, AlertTriangle} from "lucide-react";

import { scanApi } from '../lib/api/scanner';
import { useAuth } from '../contexts/AuthContext';
import { Navigate } from 'react-router-dom';
import BackButton from '../components/ui/BackButton';





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

            <span className="text-slate-500">&rarr;</span>

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

          <div><span className="text-slate-500 text-xs uppercase block mb-1">Old Evidence</span><span className="font-mono text-xs break-all">{safeRender(item.old.evidence)}</span></div>

          <div><span className="text-slate-500 text-xs uppercase block mb-1">New Evidence</span><span className="font-mono text-xs break-all">{safeRender(item.new.evidence)}</span></div>

        </div>

      )}

      {(isAdded || isRemoved || isUnchanged) && f.evidence && (

        <div className="text-sm text-slate-400 mt-2 font-mono text-xs break-all">

          {safeRender(f.evidence)}

        </div>

      )}

    </div>

  );

};



export default function HistoryCompare() {
  const { canUseScanCompare, loading: authIsLoading, isAdminLoading } = useAuth();
  const authLoading = authIsLoading || isAdminLoading;

  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const scan1 = searchParams.get('scan1');
  const scan2 = searchParams.get('scan2');

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (authLoading || !canUseScanCompare) {
      return;
    }

    if (!scan1 || !scan2) {
      setError('Missing scan IDs. Please select two scans from History.');
      setLoading(false);
      return;
    }

    const fetchComparison = async () => {
      try {
        const res = await scanApi.compareScans(scan1, scan2);
        setData(res);
      } catch (err) {
        setError(err.message || 'Failed to load comparison.');
      } finally {
        setLoading(false);
      }
    };

    fetchComparison();
  }, [scan1, scan2, authLoading, canUseScanCompare]);

  if (authLoading) {
    return (
      <div className="flex justify-center p-8">
        <Loader2 className="w-8 h-8 text-indigo-500 animate-spin" />
      </div>
    );
  }

  if (!canUseScanCompare) {
    return <Navigate to="/history" replace />;
  }



  if (loading) {

    return (

      <div className="flex justify-center p-8">

        <Loader2 className="w-8 h-8 text-indigo-500 animate-spin" />

      </div>

    );

  }



  return (

    <div className="space-y-6 max-w-5xl mx-auto pb-12">

      <div className="mb-4">
        <BackButton to="/history">Back to Scan History</BackButton>
      </div>
      <div className="flex items-center gap-4">
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

                <p className="font-mono break-all">{data.target_url}</p>

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



          
          {/* Technology & Stack Changes */}
          {((data.tech_added && data.tech_added.length > 0) || 
            (data.tech_removed && data.tech_removed.length > 0) || 
            (data.tech_version_changed && data.tech_version_changed.length > 0) || 
            (data.new_cves && data.new_cves.length > 0)) && (
            <div className="mb-10 p-6 bg-slate-900 border border-slate-800 rounded-xl shadow-lg">
              <h2 className="text-xl font-black text-slate-200 mb-6 flex items-center gap-2">
                <Layers className="w-5 h-5 text-indigo-400" /> Technology & Stack Changes
              </h2>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Tech Added & Removed */}
                <div className="space-y-4">
                  {data.tech_added && data.tech_added.length > 0 && (
                    <div>
                      <h3 className="text-xs font-bold text-emerald-400 uppercase tracking-widest mb-2 flex items-center gap-1"><Plus className="w-3 h-3" /> Added</h3>
                      <div className="flex flex-wrap gap-2">
                        {data.tech_added.map((t, i) => (
                          <span key={`add-${i}`} className="px-2.5 py-1 bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 rounded text-xs font-medium">
                            {t.product} {t.version && <span className="opacity-60">{t.version}</span>}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {data.tech_removed && data.tech_removed.length > 0 && (
                    <div>
                      <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-2 flex items-center gap-1"><Minus className="w-3 h-3" /> Removed</h3>
                      <div className="flex flex-wrap gap-2">
                        {data.tech_removed.map((t, i) => (
                          <span key={`rem-${i}`} className="px-2.5 py-1 bg-slate-800 border border-slate-700 text-slate-400 rounded text-xs font-medium opacity-75">
                            {t.product}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
                
                {/* Tech Version Changes & New CVEs */}
                <div className="space-y-4">
                  {data.tech_version_changed && data.tech_version_changed.length > 0 && (
                    <div>
                      <h3 className="text-xs font-bold text-sky-400 uppercase tracking-widest mb-2 flex items-center gap-1"><Info className="w-3 h-3" /> Version Updates</h3>
                      <div className="space-y-2">
                        {data.tech_version_changed.map((t, i) => (
                          <div key={`ver-${i}`} className="text-sm bg-sky-500/5 border border-sky-500/10 px-3 py-2 rounded flex items-center gap-2">
                            <span className="font-bold text-slate-300">{t.product}</span>
                            <span className="text-slate-500 line-through text-xs">{t.old_version}</span>
                            <ArrowRight className="w-3 h-3 text-sky-500" />
                            <span className="text-sky-300 font-bold text-xs">{t.new_version}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {data.new_cves && data.new_cves.length > 0 && (
                    <div>
                      <h3 className="text-xs font-bold text-rose-400 uppercase tracking-widest mb-2 flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> New Vulnerabilities Detected</h3>
                      <div className="space-y-2">
                        {data.new_cves.map((c, i) => (
                          <div key={`cve-${i}`} className="bg-rose-500/10 border border-rose-500/20 p-3 rounded-lg">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-rose-300 font-mono font-bold text-sm">{c.cve_id}</span>
                              <span className="text-[10px] uppercase font-bold text-rose-200 bg-rose-500/30 px-1.5 rounded">{c.severity}</span>
                              <span className="text-xs text-slate-400 ml-auto">on {c.product}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

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
