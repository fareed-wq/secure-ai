import React, { useState, useEffect } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { supabase } from '../lib/supabase';
import { ShieldCheck, Lock, Loader2, CheckCircle2 } from 'lucide-react';
import { validatePassword } from '../lib/utils/passwordPolicy';
import { PasswordChecklist } from '../components/auth/PasswordChecklist';
import { useAuth } from '../contexts/AuthContext';

const ResetPassword = () => {
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);

  const { session, isRecovery, setIsRecovery } = useAuth();
  const isRecoverySession = isRecovery;
  const recoveryEmail = isRecovery && session?.user?.email ? session.user.email : '';
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    // Check if Supabase already appended an expiration/invalid error to the URL
    const hasError = location.hash.includes('error=') || location.search.includes('error=');
    if (hasError) {
      setError("Your reset link has expired or is invalid. Please request a new one.");
    }
  }, [location]);

  const handleUpdate = async (e) => {
    e.preventDefault();
    if (!isRecoverySession) {
      setError("A valid password recovery session is required.");
      return;
    }

    const { isValid } = validatePassword(password);
    if (!isValid) {
      setError("Password does not meet all requirements.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const { error: updateError } = await supabase.auth.updateUser({ password });

      if (updateError) {
        setError("Your reset link has expired or is invalid. Please request a new one.");
        console.error("Update password error:", updateError.message);
      } else {
        await supabase.auth.signOut();
        setIsRecovery(false);
        setSuccess(true);
      }
    } catch (err) {
      setError("An unexpected error occurred.");
    }

    setLoading(false);
  };

  if (success) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col justify-center py-12 sm:px-6 lg:px-8 font-sans text-slate-200">
        <div className="sm:mx-auto sm:w-full sm:max-w-md flex flex-col items-center">
          <CheckCircle2 className="w-16 h-16 text-emerald-500 mb-4" />
          <h2 className="mt-2 text-center text-3xl font-extrabold tracking-tight text-slate-50">
            Password Updated
          </h2>
          <p className="mt-2 text-center text-sm text-slate-400">
            Password updated successfully.
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
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col justify-center py-12 sm:px-6 lg:px-8 font-sans text-slate-200">
      <div className="sm:mx-auto sm:w-full sm:max-w-md flex flex-col items-center">
        <ShieldCheck className="w-16 h-16 text-indigo-500 mb-4" />
        <h2 className="mt-2 text-center text-3xl font-extrabold tracking-tight text-slate-50">
          Set New Password
        </h2>
        <p className="mt-2 text-center text-sm text-slate-400">
          {isRecoverySession ? (
            <>Resetting password for <span className="font-medium text-slate-200">{recoveryEmail}</span></>
          ) : (
            'Validating secure reset link...'
          )}
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-slate-900 py-8 px-4 shadow-xl shadow-black/50 sm:rounded-2xl sm:px-10 border border-slate-800">
          <form className="space-y-6" onSubmit={handleUpdate}>
            {!isRecoverySession && (
              <div className="bg-yellow-500/10 border border-yellow-500/20 text-yellow-400 text-sm p-3 rounded-lg">
                A valid recovery link is required to reset your password. Please click the link in your email.
              </div>
            )}
            {error && (
              <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-sm p-3 rounded-lg">
                {error}
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-slate-300">
                New Password
              </label>
              <div className="mt-1 relative rounded-md shadow-sm">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-slate-500" />
                </div>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="block w-full pl-10 bg-slate-950 border border-slate-700 rounded-lg py-2.5 text-slate-50 placeholder-slate-500 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                  placeholder="••••••••"
                  maxLength={72}
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300">
                Confirm New Password
              </label>
              <div className="mt-1 relative rounded-md shadow-sm">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-slate-500" />
                </div>
                <input
                  type="password"
                  required
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="block w-full pl-10 bg-slate-950 border border-slate-700 rounded-lg py-2.5 text-slate-50 placeholder-slate-500 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                  placeholder="••••••••"
                  maxLength={72}
                />
              </div>
            </div>

            <PasswordChecklist password={password} confirmPassword={confirmPassword} showConfirm={true} />

            <div>
              <button
                type="submit"
                disabled={loading || !isRecoverySession || !password || !validatePassword(password).isValid || password !== confirmPassword}
                className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Update Password'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default ResetPassword;
