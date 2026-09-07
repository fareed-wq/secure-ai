import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { supabase } from '../lib/supabase';
import { useNavigate } from 'react-router-dom';
import { User, Building, Mail, Save, Loader2, Lock, LogOut, Eye, EyeOff, BadgeCheck } from 'lucide-react';
import { validatePassword } from '../lib/utils/passwordPolicy';
import { PasswordChecklist } from '../components/auth/PasswordChecklist';

const Settings = () => {
  const { user, signOut } = useAuth();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(false);
  const [passwordLoading, setPasswordLoading] = useState(false);

  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  const [formData, setFormData] = useState({
    fullName: user?.user_metadata?.full_name || '',
    company: user?.user_metadata?.company || '',
    email: user?.email || '',
  });

  const [savedProfile, setSavedProfile] = useState({
    fullName: user?.user_metadata?.full_name || '',
    company: user?.user_metadata?.company || '',
  });

  const isProfileDirty = formData.fullName !== savedProfile.fullName || formData.company !== savedProfile.company;
  const isEmailVerified = user?.email_confirmed_at != null;

  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });

  const [showCurrent, setShowCurrent] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);

  const handleSaveProfile = async (e) => {
    e.preventDefault();
    if (!isProfileDirty) return;

    setLoading(true);
    setError(null);
    setSuccess(null);

    const { error: updateError } = await supabase.auth.updateUser({
      data: {
        full_name: formData.fullName,
        company: formData.company
      }
    });

    if (updateError) {
      setError(updateError.message || 'Failed to update profile. Please try again.');
    } else {
      setSuccess('Profile updated successfully.');
      setSavedProfile({ fullName: formData.fullName, company: formData.company });
    }
    setLoading(false);
  };

  const handleSavePassword = async (e) => {
    e.preventDefault();

    if (!passwordData.currentPassword) {
      setError('Please enter your current password.');
      return;
    }

    if (passwordData.currentPassword === passwordData.newPassword) {
      setError('New password must be different from your current password.');
      return;
    }

    const { isValid } = validatePassword(passwordData.newPassword);
    if (!isValid) {
      setError('Password does not meet all requirements.');
      return;
    }
    if (passwordData.newPassword !== passwordData.confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setPasswordLoading(true);
    setError(null);
    setSuccess(null);

    const { error: updateError } = await supabase.auth.updateUser({
      password: passwordData.newPassword,
      current_password: passwordData.currentPassword
    });

    if (updateError) {
      const errMsg = updateError.message?.toLowerCase() || '';
      if (errMsg.includes("invalid password") || errMsg.includes("invalid current password") || errMsg.includes("incorrect password") || errMsg.includes("current password required")) {
        setError("Your current password is incorrect.");
      } else if (errMsg.includes("different from the old password") || errMsg.includes("different from the previous")) {
        setError("Your new password must be different from your current password.");
      } else if (updateError.status === 401 || updateError.status === 403) {
        setError("Session expired or reauthentication required. Please sign in again.");
      } else {
        setError('Failed to update password. Please try again.');
      }
    } else {
      setSuccess('Password updated successfully.');
      setPasswordData({ currentPassword: '', newPassword: '', confirmPassword: '' });
      setShowCurrent(false);
      setShowNew(false);
      setShowConfirm(false);
    }
    setPasswordLoading(false);
  };

  const handleSignOut = async () => {
    await signOut();
    navigate('/login');
  };

  return (
    <div className="max-w-4xl space-y-6 text-slate-200">
      <div>
        <h1 className="text-3xl font-bold text-slate-50 tracking-tight">Account Settings</h1>
        <p className="text-slate-400 mt-1">Manage your profile and account security.</p>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-sm p-4 rounded-lg">
          {error}
        </div>
      )}

      {success && (
        <div className="bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-sm p-4 rounded-lg">
          {success}
        </div>
      )}

      {/* Profile Section */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="p-6 border-b border-slate-800">
          <h2 className="text-lg font-semibold text-slate-50">Profile Information</h2>
        </div>

        <div className="p-6">
          <form className="space-y-6" onSubmit={handleSaveProfile}>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label htmlFor="fullName" className="block text-sm font-medium text-slate-300">Full Name</label>
                <div className="mt-1 relative rounded-md shadow-sm">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <User className="h-5 w-5 text-slate-500" />
                  </div>
                  <input
                    type="text"
                    required
                    value={formData.fullName}
                    onChange={(e) => setFormData({...formData, fullName: e.target.value})}
                    className="block w-full pl-10 bg-slate-950 border border-slate-700 rounded-lg py-2.5 text-slate-50 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                  />
                </div>
              </div>

              <div>
                <label htmlFor="company" className="block text-sm font-medium text-slate-300">Company</label>
                <div className="mt-1 relative rounded-md shadow-sm">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <Building className="h-5 w-5 text-slate-500" />
                  </div>
                  <input
                    id="company"
                    type="text"
                    value={formData.company}
                    onChange={(e) => setFormData({...formData, company: e.target.value})}
                    className="block w-full pl-10 bg-slate-950 border border-slate-700 rounded-lg py-2.5 text-slate-50 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                  />
                </div>
              </div>

              <div className="md:col-span-2">
                <label htmlFor="email" className="block text-sm font-medium text-slate-300">Email Address (Read-only)</label>
                <div className="mt-1 relative rounded-md shadow-sm opacity-60">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <Mail className="h-5 w-5 text-slate-500" />
                  </div>
                  <input
                    id="email"
                    type="email"
                    disabled
                    readOnly
                    value={formData.email}
                    className="block w-full pl-10 bg-slate-950 border border-slate-700 rounded-lg py-2.5 text-slate-400 cursor-not-allowed sm:text-sm"
                  />
                  {isEmailVerified && (
                    <div className="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                      <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-400 bg-emerald-400/10 px-2 py-0.5 rounded border border-emerald-400/20">
                        <BadgeCheck className="w-3.5 h-3.5" />
                        Verified
                      </span>
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                type="submit"
                disabled={loading || !isProfileDirty}
                className="flex items-center gap-2 px-6 py-2.5 bg-indigo-500 hover:bg-indigo-600 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                Save Profile
              </button>
            </div>
          </form>
        </div>
      </div>

      {/* Security Section */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="p-6 border-b border-slate-800">
          <h2 className="text-lg font-semibold text-slate-50">Security</h2>
        </div>

        <div className="p-6">
          <form className="space-y-6" onSubmit={handleSavePassword}>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label htmlFor="currentPassword" className="block text-sm font-medium text-slate-300">Current Password</label>
                <div className="mt-1 relative rounded-md shadow-sm">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <Lock className="h-5 w-5 text-slate-500" />
                  </div>
                  <input
                    id="currentPassword"
                    type={showCurrent ? "text" : "password"}
                    autoComplete="current-password"
                    required
                    value={passwordData.currentPassword}
                    onChange={(e) => setPasswordData({...passwordData, currentPassword: e.target.value})}
                    className="block w-full pl-10 pr-10 bg-slate-950 border border-slate-700 rounded-lg py-2.5 text-slate-50 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm placeholder-slate-600"
                    placeholder="••••••••"
                  />
                  <button
                    type="button"
                    onClick={() => setShowCurrent(!showCurrent)}
                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-500 hover:text-slate-300 focus:outline-none"
                    aria-label={showCurrent ? "Hide current password" : "Show current password"}
                  >
                    {showCurrent ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label htmlFor="newPassword" className="block text-sm font-medium text-slate-300">New Password</label>
                <div className="mt-1 relative rounded-md shadow-sm">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <Lock className="h-5 w-5 text-slate-500" />
                  </div>
                  <input
                    id="newPassword"
                    type={showNew ? "text" : "password"}
                    autoComplete="new-password"
                    required
                    minLength={12}
                    maxLength={72}
                    value={passwordData.newPassword}
                    onChange={(e) => setPasswordData({...passwordData, newPassword: e.target.value})}
                    className="block w-full pl-10 pr-10 bg-slate-950 border border-slate-700 rounded-lg py-2.5 text-slate-50 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm placeholder-slate-600"
                    placeholder="••••••••"
                  />
                  <button
                    type="button"
                    onClick={() => setShowNew(!showNew)}
                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-500 hover:text-slate-300 focus:outline-none"
                    aria-label={showNew ? "Hide new password" : "Show new password"}
                  >
                    {showNew ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>

              <div>
                <label htmlFor="confirmPassword" className="block text-sm font-medium text-slate-300">Confirm New Password</label>
                <div className="mt-1 relative rounded-md shadow-sm">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <Lock className="h-5 w-5 text-slate-500" />
                  </div>
                  <input
                    id="confirmPassword"
                    type={showConfirm ? "text" : "password"}
                    autoComplete="new-password"
                    required
                    minLength={12}
                    maxLength={72}
                    value={passwordData.confirmPassword}
                    onChange={(e) => setPasswordData({...passwordData, confirmPassword: e.target.value})}
                    className="block w-full pl-10 pr-10 bg-slate-950 border border-slate-700 rounded-lg py-2.5 text-slate-50 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm placeholder-slate-600"
                    placeholder="••••••••"
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirm(!showConfirm)}
                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-500 hover:text-slate-300 focus:outline-none"
                    aria-label={showConfirm ? "Hide confirmation password" : "Show confirmation password"}
                  >
                    {showConfirm ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>
            </div>

            <PasswordChecklist password={passwordData.newPassword} confirmPassword={passwordData.confirmPassword} showConfirm={true} />

            <div className="pt-2 flex justify-end">
              <button
                type="submit"
                disabled={
                  passwordLoading ||
                  !passwordData.currentPassword ||
                  !passwordData.newPassword ||
                  passwordData.currentPassword === passwordData.newPassword ||
                  !validatePassword(passwordData.newPassword).isValid ||
                  passwordData.newPassword !== passwordData.confirmPassword
                }
                className="flex items-center gap-2 px-6 py-2.5 bg-slate-800 hover:bg-slate-700 text-white border border-slate-700 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
              >
                {passwordLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                Update Password
              </button>
            </div>
          </form>
        </div>
      </div>

      {/* Account Section */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="p-6 border-b border-slate-800">
          <h2 className="text-lg font-semibold text-slate-50">Session</h2>
        </div>
        <div className="p-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <p className="text-sm text-slate-300 font-medium">Sign Out</p>
              <p className="text-sm text-slate-500 mt-1">End your current session safely.</p>
            </div>
            <button
              onClick={handleSignOut}
              className="flex items-center justify-center gap-2 px-6 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded-lg text-sm font-medium transition-colors"
            >
              <LogOut className="w-4 h-4" />
              Sign Out
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
