import React from 'react';
import { Link } from 'react-router-dom';
import { CheckCircle2 } from 'lucide-react';

const EmailConfirmed = () => {
  return (
    <div className="min-h-screen bg-slate-950 flex flex-col justify-center py-12 sm:px-6 lg:px-8 font-sans text-slate-200">
      <div className="sm:mx-auto sm:w-full sm:max-w-md flex flex-col items-center">
        <CheckCircle2 className="w-16 h-16 text-emerald-500 mb-4" />
        <h2 className="mt-2 text-center text-3xl font-extrabold tracking-tight text-slate-50">
          Email Verified Successfully
        </h2>
        <p className="mt-2 text-center text-sm text-slate-400">
          Your email address has been confirmed and your account is ready to use.
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-slate-900 py-8 px-4 shadow-xl shadow-black/50 sm:rounded-2xl sm:px-10 border border-slate-800 text-center">
          <Link
            to="/login"
            className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors"
          >
            Continue to Sign In
          </Link>
        </div>
        
        <div className="mt-6 text-center">
          <Link to="/" className="text-sm font-medium text-slate-400 hover:text-slate-300 transition-colors">
            &larr; Back to Home
          </Link>
        </div>
      </div>
    </div>
  );
};

export default EmailConfirmed;
