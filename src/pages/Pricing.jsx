import React, { useEffect } from 'react';
import { CreditCard, Clock, CheckCircle2, Shield, Zap, Building2 } from 'lucide-react';

const Pricing = () => {
  useEffect(() => {
    document.title = "Pricing | URLScannerOnline";
  }, []);

  const plannedPlans = [
    {
      name: "Starter",
      icon: <Shield className="w-6 h-6 text-indigo-400" />,
      features: [
        "Basic security scanning",
        "Security reports",
        "Scan history"
      ]
    },
    {
      name: "Professional",
      icon: <Zap className="w-6 h-6 text-purple-400" />,
      features: [
        "Advanced scanning",
        "Scan comparison",
        "Detailed findings",
        "Exportable reports"
      ]
    },
    {
      name: "Business",
      icon: <Building2 className="w-6 h-6 text-emerald-400" />,
      features: [
        "Team access",
        "Higher scan limits",
        "Centralized reporting"
      ]
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
            Pricing
          </div>
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-black text-slate-50 mb-6 tracking-tight">
            Plans are coming soon
          </h1>
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400 font-medium mb-6">
            <Clock className="w-5 h-5" />
            In Development
          </div>
          <div className="text-lg md:text-xl text-slate-400 leading-relaxed max-w-2xl mx-auto space-y-4">
            <p>
              We're currently finalizing our plans and pricing for URLScannerOnline.
            </p>
            <p>
              Our goal is to offer flexible options for individuals, security professionals, and organizations, with pricing based on features, scan usage, and reporting capabilities.
            </p>
            <p className="text-slate-500 text-base">
              Pricing and plan details will be published once the service is ready for public use.
            </p>
          </div>
        </div>
      </section>

      {/* Planned Plans */}
      <section className="max-w-6xl mx-auto px-4 md:px-0">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold text-slate-50 mb-4">Plans in Development</h2>
          <p className="text-slate-400 max-w-2xl mx-auto">
            The following tiers represent our planned feature breakdown. These plans are not currently available and details are subject to change.
          </p>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {plannedPlans.map((plan, idx) => (
            <div 
              key={idx} 
              className="flex flex-col rounded-3xl border border-slate-800 bg-slate-900/50 p-8 select-none"
            >
              <div className="w-12 h-12 rounded-xl border border-slate-700 bg-slate-800/50 flex items-center justify-center mb-6">
                {plan.icon}
              </div>
              <h3 className="text-2xl font-bold text-slate-50 mb-2">{plan.name}</h3>
              <div className="flex-1 mt-6">
                <ul className="space-y-4">
                  {plan.features.map((feature, fIdx) => (
                    <li key={fIdx} className="flex items-start gap-3 text-slate-300">
                      <CheckCircle2 className="w-5 h-5 text-indigo-400/70 shrink-0 mt-0.5" />
                      <span>{feature}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
};

export default Pricing;
