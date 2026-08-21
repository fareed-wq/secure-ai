import React, { useState, useEffect } from 'react';
import { supabase } from '../lib/supabase';

const AuthDiagnostic = () => {
  const [session, setSession] = useState(null);
  const [header, setHeader] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchSession = async () => {
      try {
        const { data: { session } } = await supabase.auth.getSession();
        setSession(session);
        
        if (session && session.access_token) {
          // Decode ONLY the JWT header
          const parts = session.access_token.split('.');
          if (parts.length > 0) {
            const decodedHeader = atob(parts[0]);
            const parsed = JSON.parse(decodedHeader);
            setHeader({
              alg: parsed.alg || 'unknown',
              kid: parsed.kid || null,
              typ: parsed.typ || null
            });
          }
        }
      } catch (e) {
        console.error("Error reading session:", e);
      } finally {
        setLoading(false);
      }
    };
    fetchSession();
  }, []);

  if (loading) {
    return <div className="p-8 text-white">Loading diagnostic...</div>;
  }

  if (!session) {
    return (
      <div className="p-8 bg-slate-950 min-h-screen text-slate-300 font-mono">
        <h1 className="text-xl font-bold text-red-500 mb-4">Auth Diagnostic</h1>
        <p>No authenticated session found. Please log in first.</p>
        <p className="mt-4 text-xs text-slate-600 bg-slate-900 inline-block p-2 rounded">
          Temporary authentication diagnostic — remove after JWT signing verification.
        </p>
      </div>
    );
  }

  return (
    <div className="p-8 bg-slate-950 min-h-screen text-slate-300 font-mono">
      <h1 className="text-xl font-bold text-emerald-400 mb-4">Auth Diagnostic</h1>
      <div className="bg-slate-900 p-6 rounded-lg border border-slate-800 shadow-xl max-w-xl">
        <h2 className="text-sm font-semibold text-slate-400 mb-2">JWT HEADER</h2>
        {header ? (
          <pre className="bg-slate-950 p-4 rounded text-emerald-300 overflow-x-auto text-sm border border-slate-800">
            {JSON.stringify(header, null, 2)}
          </pre>
        ) : (
          <p className="text-red-400">Failed to parse JWT header.</p>
        )}
      </div>
      <p className="mt-8 text-xs text-amber-600 bg-amber-900/20 inline-block p-2 rounded border border-amber-900/50">
        Temporary authentication diagnostic — remove after JWT signing verification.
      </p>
    </div>
  );
};

export default AuthDiagnostic;
