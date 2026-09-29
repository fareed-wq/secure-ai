import React, { useEffect, useState, useRef } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { CheckCircle2, XCircle, Loader2 } from 'lucide-react';
import { supabase } from '../lib/supabase';

const EmailConfirmed = () => {
  const [errorMsg, setErrorMsg] = useState(null);
  const [loading, setLoading] = useState(true);
  const location = useLocation();
  const hasVerified = useRef(false);

  useEffect(() => {
    if (hasVerified.current) return;
    hasVerified.current = true;

    const searchParams = new URLSearchParams(location.search);
    const tokenHash = searchParams.get('token_hash');
    const type = searchParams.get('type') || 'email';
    const errorQuery = searchParams.get('error');

    const hashParams = new URLSearchParams(location.hash.substring(1));
    const hashError = hashParams.get('error');

    if (errorQuery || hashError) {
      setErrorMsg("This confirmation link is invalid or has expired.");
      setLoading(false);
      return;
    }

    if (tokenHash) {
      supabase.auth.verifyOtp({
        token_hash: tokenHash,
        type: type
      }).then(({ data, error }) => {
        if (error) {
          setErrorMsg("This confirmation link is invalid, expired, or has already been used.");
        } else {
          supabase.auth.signOut().catch(() => {});
        }
        setLoading(false);
      }).catch((err) => {
        
        setErrorMsg("An error occurred during verification.");
        setLoading(false);
      });
    } else {
      const hashType = hashParams.get('type');
      const accessToken = hashParams.get('access_token');

      if (hashType === 'signup' && accessToken) {
        supabase.auth.signOut().catch(() => {});
      }
      setLoading(false);
    }
  }, [location.search, location.hash]);

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col justify-center py-12 sm:px-6 lg:px-8 font-sans text-slate-200">
      <div className="sm:mx-auto sm:w-full sm:max-w-md flex flex-col items-center">
        {loading ? (
          <>
            <Loader2 className="w-16 h-16 text-indigo-500 mb-4 animate-spin" />
            <h2 className="mt-2 text-center text-3xl font-extrabold tracking-tight text-slate-50">
              Verifying...
            </h2>
            <p className="mt-2 text-center text-sm text-slate-400">
              Please wait while we confirm your email address.
            </p>
          </>
        ) : errorMsg ? (
          <>
            <XCircle className="w-16 h-16 text-rose-500 mb-4" />
            <h2 className="mt-2 text-center text-3xl font-extrabold tracking-tight text-slate-50">
              Confirmation Failed
            </h2>
            <p className="mt-2 text-center text-sm text-rose-400">
              {errorMsg}
            </p>
          </>
        ) : (
          <>
            <CheckCircle2 className="w-16 h-16 text-emerald-500 mb-4" />
            <h2 className="mt-2 text-center text-3xl font-extrabold tracking-tight text-slate-50">
              Email Confirmed Successfully
            </h2>
            <p className="mt-2 text-center text-sm text-slate-400">
              Your email address has been verified.<br />
              Your URLScanOnline account is now ready to use.
            </p>
          </>
        )}
      </div>

      {!loading && (
        <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
          <div className="bg-slate-900 py-8 px-4 shadow-xl shadow-black/50 sm:rounded-2xl sm:px-10 border border-slate-800 text-center">
            <Link
              to="/login"
              className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors"
            >
              Go to Login
            </Link>
          </div>
        </div>
      )}
    </div>
  );
};

export default EmailConfirmed;
