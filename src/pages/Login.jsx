import BackButton from '../components/ui/BackButton';
import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { supabase } from '../lib/supabase';
import { ShieldCheck, Mail, Lock, Loader2, Eye, EyeOff } from 'lucide-react';
import { Turnstile } from '@marsidev/react-turnstile';

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [captchaToken, setCaptchaToken] = useState(null);
  const captchaPromiseRef = React.useRef(null);
  const [isNarrowViewport, setIsNarrowViewport] = useState(
    typeof window !== 'undefined' ? window.innerWidth < 360 : false
  );
  
  // Phase 1 Recovery State
  const [verifyMode, setVerifyMode] = useState(false);
  const [otpToken, setOtpToken] = useState('');
  const [resendCooldown, setResendCooldown] = useState(0);

  useEffect(() => {
    const handleResize = () => setIsNarrowViewport(window.innerWidth < 360);
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  useEffect(() => {
    let timer;
    if (resendCooldown > 0) {
      timer = setTimeout(() => setResendCooldown(c => c - 1), 1000);
    }
    return () => clearTimeout(timer);
  }, [resendCooldown]);

  const turnstileRef = React.useRef();
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    const { error } = await supabase.auth.signInWithPassword({
      email,
      password,
      options: { captchaToken }
    });

    turnstileRef.current?.reset();
    setCaptchaToken(null);

    if (error) {
      if (error.message === 'Email not confirmed') {
        setError('Please check your email to verify your account before signing in.');

        // Wait for a fresh token
        const freshToken = await new Promise((resolve) => {
          captchaPromiseRef.current = resolve;
          setTimeout(() => resolve(null), 10000);
        });

        if (!freshToken) {
          setError('Please check your email to verify your account. (Auto-send failed - please use Resend).');
          setVerifyMode(true);
          setResendCooldown(0);
          setLoading(false);
          return;
        }

        // Trigger recovery OTP
        const { error: otpError } = await supabase.auth.signInWithOtp({
          email,
          options: { shouldCreateUser: false, captchaToken: freshToken }
        });

        turnstileRef.current?.reset();
        setCaptchaToken(null);

        if (!otpError) {
          setVerifyMode(true);
          setResendCooldown(60);
          setError(null);
        } else {
          setError(otpError.message || 'Failed to send recovery verification code.');
        }
      } else if (error.message === 'Invalid login credentials') {
        setError('Incorrect email or password.');
      } else {
        setError('Unable to sign in. Please try again.');
      }
    } else {
      navigate('/dashboard');
    }
    setLoading(false);
  };

  const handleVerify = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const { data, error } = await supabase.auth.verifyOtp({
        email,
        token: otpToken,
        type: 'email'
      });

      if (error) throw error;
      if (data?.session) {
        navigate('/dashboard');
      } else {
        throw new Error('Failed to establish session.');
      }
    } catch (err) {
      setError(err.message || 'Invalid verification code.');
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    if (resendCooldown > 0) return;
    setLoading(true);
    setError(null);
    try {
      setCaptchaToken(null);
      turnstileRef.current?.reset();
      const freshToken = await new Promise((resolve) => {
        captchaPromiseRef.current = resolve;
        setTimeout(() => resolve(null), 10000);
      });

      if (!freshToken) {
        throw new Error('Security check failed. Please refresh and try again.');
      }

      const { error } = await supabase.auth.signInWithOtp({
        email,
        options: { shouldCreateUser: false, captchaToken: freshToken }
      });

      setCaptchaToken(null);
      turnstileRef.current?.reset();

      if (error) throw error;
      setResendCooldown(60);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (verifyMode) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col justify-center py-12 sm:px-6 lg:px-8 font-sans relative overflow-hidden">
        <div className="sm:mx-auto sm:w-full sm:max-w-md relative z-10">
          <div className="flex justify-center">
            <div className="w-16 h-16 bg-emerald-500/10 rounded-full flex items-center justify-center border border-emerald-500/20 shadow-[0_0_15px_rgba(16,185,129,0.2)]">
              <Mail className="h-8 w-8 text-emerald-400" />
            </div>
          </div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-slate-50 tracking-tight">
            Verify your email
          </h2>
          <p className="mt-2 text-center text-sm text-slate-400">
            We've sent a verification code to <span className="font-medium text-slate-300">{email}</span>.
          </p>
        </div>

        <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
          <div className="bg-slate-900 py-8 px-4 shadow-xl sm:rounded-2xl sm:px-10 border border-slate-800">
            <form className="space-y-6" onSubmit={handleVerify}>
              {error && (
                <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-sm p-3 rounded-lg">
                  {error}
                </div>
              )}
              <div>
                <label className="block text-sm font-medium text-slate-300">Verification Code</label>
                <input
                  type="text"
                  required
                  value={otpToken}
                  onChange={(e) => setOtpToken(e.target.value)}
                  className="mt-1 block w-full bg-slate-950 border border-slate-700 rounded-lg py-2.5 px-3 text-slate-50 sm:text-lg tracking-widest text-center focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
                  placeholder="000000"
                  maxLength={6}
                />
              </div>
              <button
                type="submit"
                disabled={loading || !otpToken}
                className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-slate-900 bg-emerald-500 hover:bg-emerald-400 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-emerald-500 disabled:opacity-50"
              >
                {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Verify Account'}
              </button>
            </form>
            <div className="mt-6 flex flex-col space-y-3">
              <button
                type="button"
                onClick={handleResend}
                disabled={resendCooldown > 0 || loading}
                className="w-full text-sm text-slate-400 hover:text-slate-300 disabled:opacity-50"
              >
                {resendCooldown > 0 ? `Resend code in ${resendCooldown}s` : 'Resend code'}
              </button>
              <button
                type="button"
                onClick={() => { setVerifyMode(false); setOtpToken(''); setError(null); }}
                className="w-full text-sm text-slate-500 hover:text-slate-400"
              >
                Back to sign in
              </button>
            </div>
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
          Sign in to your account
        </h2>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-slate-900 py-8 px-4 shadow-xl shadow-black/50 sm:rounded-2xl sm:px-10 border border-slate-800">
          <form className="space-y-6" onSubmit={handleLogin}>
            {error && (
              <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-sm p-3 rounded-lg flex justify-between items-center">
                <span>{error}</span>
                {error.includes('verify your account') && (
                  <button 
                    type="button" 
                    onClick={async () => {
                      setLoading(true);
                      setCaptchaToken(null);
                      turnstileRef.current?.reset();
                      const freshToken = await new Promise((resolve) => {
                        captchaPromiseRef.current = resolve;
                        setTimeout(() => resolve(null), 10000);
                      });
                      if (!freshToken) {
                        setError('Security check failed. Please refresh and try again.');
                        setLoading(false);
                        return;
                      }
                      const { error: otpError } = await supabase.auth.signInWithOtp({ email, options: { shouldCreateUser: false, captchaToken: freshToken } });
                      setCaptchaToken(null);
                      turnstileRef.current?.reset();
                      if (!otpError) { setVerifyMode(true); setResendCooldown(60); setError(null); }
                      else setError(otpError.message);
                      setLoading(false);
                    }}
                    className="ml-2 text-indigo-400 hover:text-indigo-300 underline"
                  >
                    Resend Code
                  </button>
                )}
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-slate-300">
                Email address
              </label>
              <div className="mt-1 relative rounded-md shadow-sm">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Mail className="h-5 w-5 text-slate-500" />
                </div>
                <input
                  type="email"
                  autoComplete="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="block w-full pl-10 bg-slate-950 border border-slate-700 rounded-lg py-2.5 text-slate-50 placeholder-slate-500 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                  placeholder="you@example.com"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300">
                Password
              </label>
              <div className="mt-1 relative rounded-md shadow-sm">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-slate-500" />
                </div>
                <input
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="block w-full pl-10 pr-10 bg-slate-950 border border-slate-700 rounded-lg py-2.5 text-slate-50 placeholder-slate-500 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                  placeholder="••••••••"
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-500 hover:text-slate-300 focus:outline-none"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <input
                  id="remember-me"
                  name="remember-me"
                  type="checkbox"
                  className="h-4 w-4 text-indigo-500 border-slate-700 rounded bg-slate-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-900"
                />
                <label htmlFor="remember-me" className="ml-2 block text-sm text-slate-300">
                  Remember me
                </label>
              </div>

              <div className="text-sm">
                <Link to="/forgot-password" className="font-medium text-indigo-400 hover:text-indigo-300">
                  Forgot your password?
                </Link>
              </div>
            </div>

            <div>
              <div className="flex justify-center mb-6">
                <Turnstile
                  ref={turnstileRef}
                  siteKey={import.meta.env.VITE_TURNSTILE_SITE_KEY}
                  options={{ size: isNarrowViewport ? "compact" : "flexible" }}
                  onSuccess={(token) => {
                    setCaptchaToken(token);
                    if (captchaPromiseRef.current) {
                      captchaPromiseRef.current(token);
                      captchaPromiseRef.current = null;
                    }
                  }}
                  onExpire={() => setCaptchaToken(null)}
                  onError={() => setCaptchaToken(null)}
                />
              </div>
              <button
                type="submit"
                disabled={loading || !captchaToken}
                className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Sign in'}
              </button>
            </div>
          </form>
        </div>

        <div className="mt-6 text-center">
          <BackButton to="/">Back to Home</BackButton>
        </div>
      </div>
    </div>
  );
};

export default Login;
