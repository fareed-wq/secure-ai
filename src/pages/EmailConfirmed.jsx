import React, { useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { CheckCircle2, XCircle, Loader2, Mail } from 'lucide-react';
import { supabase } from '../lib/supabase';

const EmailConfirmed = () => {
  const [status, setStatus] = useState('initial'); // 'initial', 'ready', 'verifying', 'success', 'error'
  const [errorMsg, setErrorMsg] = useState(null);
  const [tokenData, setTokenData] = useState(null);
  const location = useLocation();

  useEffect(() => {
    const searchParams = new URLSearchParams(location.search);
    const tokenHash = searchParams.get('token_hash');
    const type = searchParams.get('type') || 'email';
    const errorQuery = searchParams.get('error');

    const hashParams = new URLSearchParams(location.hash.substring(1));
    const hashError = hashParams.get('error');

    if (errorQuery || hashError) {
      setErrorMsg("This confirmation link is invalid or has expired.");
      setStatus('error');
      return;
    }

    if (tokenHash) {
      // Ready for user-initiated verification
      setTokenData({ tokenHash, type });
      setStatus('ready');
    } else {
      // Legacy implicit flow (token already verified prior to redirect)
      const hashType = hashParams.get('type');
      const accessToken = hashParams.get('access_token');

      if (hashType === 'signup' && accessToken) {
        supabase.auth.signOut().catch(() => {});
        setStatus('success');
      } else {
        setErrorMsg("No valid confirmation token was found in the link.");
        setStatus('error');
      }
    }
  }, [location.search, location.hash]);

  const handleVerify = () => {
    if (!tokenData || status === 'verifying') return;

    setStatus('verifying');
    
    supabase.auth.verifyOtp({
      token_hash: tokenData.tokenHash,
      type: tokenData.type
    }).then(({ error }) => {
      if (error) {
        setErrorMsg("This confirmation link is invalid, expired, or has already been used.");
        setStatus('error');
      } else {
        supabase.auth.signOut().catch(() => {});
        setStatus('success');
      }
    }).catch(() => {
      setErrorMsg("An error occurred during verification.");
      setStatus('error');
    });
  };

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col justify-center py-12 sm:px-6 lg:px-8 font-sans text-slate-200">
      <div className="sm:mx-auto sm:w-full sm:max-w-md flex flex-col items-center">
        {status === 'verifying' ? (
          <>
            <Loader2 className="w-16 h-16 text-indigo-500 mb-4 animate-spin" />
            <h2 className="mt-2 text-center text-3xl font-extrabold tracking-tight text-slate-50">
              Verifying...
            </h2>
            <p className="mt-2 text-center text-sm text-slate-400">
              Please wait while we confirm your email address.
            </p>
          </>
        ) : status === 'ready' ? (
          <>
            <Mail className="w-16 h-16 text-indigo-500 mb-4" />
            <h2 className="mt-2 text-center text-3xl font-extrabold tracking-tight text-slate-50">
              Confirm your email
            </h2>
            <p className="mt-2 text-center text-sm text-slate-400">
              Click the button below to verify your email address.
            </p>
          </>
        ) : status === 'error' ? (
          <>
            <XCircle className="w-16 h-16 text-rose-500 mb-4" />
            <h2 className="mt-2 text-center text-3xl font-extrabold tracking-tight text-slate-50">
              Confirmation Failed
            </h2>
            <p className="mt-2 text-center text-sm text-rose-400">
              {errorMsg}
            </p>
          </>
        ) : status === 'success' ? (
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
        ) : null}
      </div>

      {(status === 'ready' || status === 'error' || status === 'success') && (
        <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
          <div className="bg-slate-900 py-8 px-4 shadow-xl shadow-black/50 sm:rounded-2xl sm:px-10 border border-slate-800 text-center">
            {status === 'ready' ? (
              <button
                onClick={handleVerify}
                disabled={status === 'verifying'}
                className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors"
              >
                Confirm Email
              </button>
            ) : (
              <Link
                to="/login"
                className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors"
              >
                Go to Login
              </Link>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default EmailConfirmed;
