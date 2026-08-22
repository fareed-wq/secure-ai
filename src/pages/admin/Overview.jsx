import React, { useEffect, useState } from 'react';
import { adminApi } from '../../lib/api/admin';
import { Loader2, Users, Activity, ShieldAlert, CreditCard } from 'lucide-react';

export default function Overview() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchOverview = async () => {
      try {
        const result = await adminApi.getOverview();
        setData(result);
      } catch (err) {
        setError(err.message || 'Failed to load overview data');
      } finally {
        setLoading(false);
      }
    };
    fetchOverview();
  }, []);

  if (loading) {
    return <div className="flex justify-center p-8"><Loader2 className="w-8 h-8 text-indigo-500 animate-spin" /></div>;
  }

  if (error) {
    return <div className="p-4 bg-red-500/10 border border-red-500/50 rounded text-red-400">{error}</div>;
  }

  if (!data) return null;

  const cards = [
    { title: 'Total Users', value: data.total_users, icon: Users, color: 'text-blue-400' },
    { title: 'Free Users', value: data.free_users, icon: Users, color: 'text-slate-400' },
    { title: 'Professional Users', value: data.professional_users, icon: CreditCard, color: 'text-indigo-400' },
    { title: 'Scans Today', value: data.scans_today, icon: Activity, color: 'text-green-400' },
    { title: 'Scans This Week', value: data.scans_this_week, icon: Activity, color: 'text-emerald-400' },
    { title: 'Recent Failures', value: data.recent_failures, icon: ShieldAlert, color: 'text-red-400' }
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Overview</h1>
      
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {cards.map((card, i) => {
          if (card.value === undefined || card.value === null) return null;
          const Icon = card.icon;
          return (
            <div key={i} className="bg-slate-900 border border-slate-800 rounded-lg p-6 flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400 mb-1">{card.title}</p>
                <h3 className="text-2xl font-bold">{card.value}</h3>
              </div>
              <Icon className={`w-8 h-8 ${card.color} opacity-80`} />
            </div>
          );
        })}
      </div>
    </div>
  );
}
