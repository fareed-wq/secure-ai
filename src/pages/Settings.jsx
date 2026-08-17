import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { supabase } from '../lib/supabase';
import { useNavigate } from 'react-router-dom';
import { User, Building, Mail, Save, Loader2, Lock, LogOut } from 'lucide-react';

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

  const [passwordData, setPasswordData] = useState({
    newPassword: '',
    confirmPassword: ''
  });

  const handleSaveProfile = async (e) => {
    e.preventDefault();
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
    }
    setLoading(false);
  };

  const handleSavePassword = async (e) => {
    e.preventDefault();

    if (passwordData.newPassword.length < 8) {
      setError('Password must be at least 8 characters long.');
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
      password: passwordData.newPassword
    });

    if (updateError) {
      setError(updateError.message || 'Failed to update password. Please try again.');
    } else {
      setSuccess('Password updated successfully.');
      setPasswordData({ newPassword: '', confirmPassword: '' });
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
        <p className="text-slate-400 mt-1">Manage your profile, security, and preferences.</p>
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
                <label className="block text-sm font-medium text-slate-300">Full Name</label>
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
                <label className="block text-sm font-medium text-slate-300">Company</label>
                <div className="mt-1 relative rounded-md shadow-sm">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <Building className="h-5 w-5 text-slate-500" />
                  </div>
                  <input
                    type="text"
                    value={formData.company}
                    onChange={(e) => setFormData({...formData, company: e.target.value})}
                    className="block w-full pl-10 bg-slate-950 border border-slate-700 rounded-lg py-2.5 text-slate-50 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                  />
                </div>
              </div>

              <div className="md:col-span-2">
                <label className="block text-sm font-medium text-slate-300">Email Address (Read-only)</label>
                <div className="mt-1 relative rounded-md shadow-sm opacity-60">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <Mail className="h-5 w-5 text-slate-500" />
                  </div>
                  <input
                    type="email"
                    disabled
                    value={formData.email}
                    className="block w-full pl-10 bg-slate-950 border border-slate-700 rounded-lg py-2.5 text-slate-400 cursor-not-allowed sm:text-sm"
                  />
                </div>
              </div>
            </div>

            <div className="pt-4 flex justify-end">
              <button
                type="submit"
                disabled={loading}
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
                <label className="block text-sm font-medium text-slate-300">New Password</label>
                <div className="mt-1 relative rounded-md shadow-sm">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <Lock className="h-5 w-5 text-slate-500" />
                  </div>
                  <input
                    type="password"
                    required
                    minLength={8}
                    value={passwordData.newPassword}
                    onChange={(e) => setPasswordData({...passwordData, newPassword: e.target.value})}
                    className="block w-full pl-10 bg-slate-950 border border-slate-700 rounded-lg py-2.5 text-slate-50 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm placeholder-slate-600"
                    placeholder="••••••••"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300">Confirm New Password</label>
                <div className="mt-1 relative rounded-md shadow-sm">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <Lock className="h-5 w-5 text-slate-500" />
                  </div>
                  <input
                    type="password"
                    required
                    minLength={8}
                    value={passwordData.confirmPassword}
                    onChange={(e) => setPasswordData({...passwordData, confirmPassword: e.target.value})}
                    className="block w-full pl-10 bg-slate-950 border border-slate-700 rounded-lg py-2.5 text-slate-50 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm placeholder-slate-600"
                    placeholder="••••••••"
                  />
                </div>
              </div>
            </div>

            <div className="pt-4 flex justify-end">
              <button
                type="submit"
                disabled={passwordLoading || !passwordData.newPassword || !passwordData.confirmPassword}
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
          <h2 className="text-lg font-semibold text-slate-50">Account Actions</h2>
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
