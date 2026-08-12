import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { User, Building, Mail, Save, Loader2 } from 'lucide-react';

const Settings = () => {
  const { user } = useAuth();
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    fullName: user?.user_metadata?.full_name || '',
    company: user?.user_metadata?.company || '',
    email: user?.email || '',
  });

  const handleSave = (e) => {
    e.preventDefault();
    setLoading(true);
    // In MVP, this is a mock save if Supabase is bypassed.
    setTimeout(() => {
      setLoading(false);
      alert('Settings saved successfully!');
    }, 1000);
  };

  return (
    <div className="max-w-4xl space-y-6 text-slate-200">
      <div>
        <h1 className="text-3xl font-bold text-slate-50 tracking-tight">Account Settings</h1>
        <p className="text-slate-400 mt-1">Manage your profile and platform preferences.</p>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="p-6 border-b border-slate-800">
          <h2 className="text-lg font-semibold text-slate-50">Profile Information</h2>
        </div>
        
        <div className="p-6">
          <form className="space-y-6" onSubmit={handleSave}>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-sm font-medium text-slate-300">Full Name</label>
                <div className="mt-1 relative rounded-md shadow-sm">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <User className="h-5 w-5 text-slate-500" />
                  </div>
                  <input
                    type="text"
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
                className="flex items-center gap-2 px-6 py-2.5 bg-indigo-500 hover:bg-indigo-600 text-white rounded-lg text-sm font-medium transition-colors"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                Save Changes
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Settings;
