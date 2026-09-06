import React from 'react';
import { CreditCard, CheckCircle2, Shield, Zap, Rocket } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useSEO } from '../hooks/useSEO';

const Pricing = () => {
  useSEO({
    title: 'Pricing & Access Plans | URLScanOnline',
    description: 'Compare URLScanOnline Guest and Free Account features and preview upcoming Paid Account capabilities including scan comparison, scheduled scans and email reports.',
    path: '/pricing'
  });

  const accessPlans = [
    {
      name: "Guest",
      status: "AVAILABLE NOW",
      statusColor: "text-emerald-400 bg-emerald-400/10 border-emerald-400/20",
      icon: <Shield className="w-6 h-6 text-indigo-400" />,
      features: [
        "Basic security scan",
        "Passive security checks",
        "Security findings and report",
        "No account required"
      ],
      ctaText: "Start Basic Scan",
      ctaLink: "/scan",
      disabled: false
    },
    {
      name: "Free Account",
      status: "AVAILABLE NOW",
      statusColor: "text-emerald-400 bg-emerald-400/10 border-emerald-400/20",
      icon: <Zap className="w-6 h-6 text-purple-400" />,
      features: [
        "Everything in Guest",
        "Advanced security scanning",
        "Scan history and saved reports",
        "Manage scans from your account"
      ],
      ctaText: "Create Free Account",
      ctaLink: "/register",
      disabled: false
    },
    {
      name: "Paid Account",
      status: "COMING SOON",
      statusColor: "text-amber-400 bg-amber-400/10 border-amber-400/20",
      icon: <Rocket className="w-6 h-6 text-amber-400" />,
      features: [
        "Everything in Free Account",
        "Scan Comparison",
        "Scheduled Scans",
        "Email Reports"
      ],
      ctaText: "Coming Soon",
      ctaLink: "#",
      disabled: true
    }
  ];

  return (
    <div className="space-y-16 pb-12">
      {/* Hero */}
      <section className="relative overflow-hidden rounded-3xl bg-slate-900 border border-slate-800 p-8 md:p-16 text-center">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-full max-w-4xl opacity-30 pointer-events-none">
          <div className="absolute inset-0 bg-gradient-to-r from-indigo-500/20 via-purple-500/20 to-blue-500/20 blur-3xl rounded-full transform -translate-y-1/2" />
        </div>
        <div className="relative z-10 max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 text-indigo-400 text-sm font-semibold mb-6">
            <CreditCard className="w-4 h-4" />
            Pricing & Access
          </div>
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-black text-slate-50 mb-6 tracking-tight">
            Choose How You Scan
          </h1>
          <div className="text-lg md:text-xl text-slate-400 leading-relaxed max-w-2xl mx-auto space-y-4">
            <p>
              Start scanning without an account, create a free account for additional features, or access more automation and comparison tools with our upcoming paid plan.
            </p>
            <p className="text-slate-500 text-base mt-6">
              Guest and Free Account access are available now. Paid Account features and pricing are currently in development.
            </p>
          </div>
        </div>
      </section>

      {/* Access Options */}
      <section className="max-w-6xl mx-auto px-4 md:px-0">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold text-slate-50 mb-4">Access Options</h2>
          <p className="text-slate-400 max-w-2xl mx-auto">
            Choose the level that fits how you use URLScanOnline. Guest and Free Account access are available today, while the Paid Account is coming soon.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {accessPlans.map((plan, idx) => (
            <div
              key={idx}
              className={`flex flex-col rounded-3xl border ${plan.disabled ? 'border-amber-500/20 bg-slate-900/40 relative overflow-hidden' : 'border-slate-800 bg-slate-900/50'} p-8`}
            >
              <div className="flex items-center justify-between mb-6">
                <div className={`w-12 h-12 rounded-xl border ${plan.disabled ? 'border-amber-500/20 bg-amber-500/10' : 'border-slate-700 bg-slate-800/50'} flex items-center justify-center`}>
                  {plan.icon}
                </div>
                <div className={`text-[10px] font-bold uppercase tracking-wider px-3 py-1 rounded-full border ${plan.statusColor}`}>
                  {plan.status}
                </div>
              </div>

              <h3 className="text-2xl font-bold text-slate-50 mb-2">{plan.name}</h3>

              {plan.disabled && (
                <div className="text-amber-400/80 font-medium text-sm mb-2">
                  Pricing to be announced
                </div>
              )}

              <div className="flex-1 mt-6">
                <ul className="space-y-4">
                  {plan.features.map((feature, fIdx) => (
                    <li key={fIdx} className={`flex items-start gap-3 ${plan.disabled ? 'text-slate-400' : 'text-slate-300'}`}>
                      <CheckCircle2 className={`w-5 h-5 shrink-0 mt-0.5 ${plan.disabled ? 'text-amber-500/50' : 'text-indigo-400/70'}`} />
                      <span>{feature}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="mt-8 pt-6 border-t border-slate-800/60">
                {plan.disabled ? (
                  <button disabled className="w-full py-3 px-4 rounded-xl font-medium text-center transition-colors bg-slate-800/50 text-slate-500 border border-slate-700 cursor-not-allowed">
                    {plan.ctaText}
                  </button>
                ) : (
                  <Link to={plan.ctaLink} className="w-full block py-3 px-4 rounded-xl font-medium text-center transition-colors bg-indigo-600 hover:bg-indigo-500 text-white shadow-md shadow-indigo-500/20">
                    {plan.ctaText}
                  </Link>
                )}
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
};

export default Pricing;
