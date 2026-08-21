import React, { useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { CheckCircle2, XCircle } from 'lucide-react';
import { supabase } from '../lib/supabase';

const EmailConfirmed = () => {
  const [errorMsg, setErrorMsg] = useState(null);
  const location = useLocation();

  useEffect(() => {
    // Supabase appends parameters in the hash for implicit flow
    const hashParams = new URLSearchParams(location.hash.substring(1));
    const error = hashParams.get('error');
    const errorDescription = hashParams.get('error_description');

    if (error) {
      setErrorMsg("This confirmation link is invalid or has expired.");
    } else {
      const type = hashParams.get('type');
      const accessToken = hashParams.get('access_token');

      if (type === 'signup' && accessToken) {
        // If it's a successful confirmation, Supabase automatically logs the user in.
        // We explicitly sign them out so they are forced to log in.
        supabase.auth.signOut().catch(console.error);
      }
    }
  }, [location.hash]);

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col justify-center py-12 sm:px-6 lg:px-8 font-sans text-slate-200">
      <div className="sm:mx-auto sm:w-full sm:max-w-md flex flex-col items-center">
        {errorMsg ? (
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
    </div>
  );
};

export default EmailConfirmed;
