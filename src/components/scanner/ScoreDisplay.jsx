import React from 'react';

const ScoreDisplay = ({ score, isWafBlocked }) => {
  return (
    <div className="bg-slate-900 border border-slate-800 p-8 rounded-3xl shadow-xl flex flex-col items-center justify-center text-center">
      <div className="relative">
        <svg className="w-40 h-40 transform -rotate-90">
          <circle cx="80" cy="80" r="70" stroke="currentColor" strokeWidth="12" fill="transparent" className="text-slate-800" />
          {!isWafBlocked && (
            <circle cx="80" cy="80" r="70" stroke="currentColor" strokeWidth="12" fill="transparent"
              strokeDasharray={2 * Math.PI * 70}
              strokeDashoffset={2 * Math.PI * 70 * (1 - score / 100)}
              className={score >= 80 ? 'text-emerald-500' : score >= 60 ? 'text-amber-500' : 'text-red-500'}
              strokeLinecap="round"
            />
          )}
          {isWafBlocked && (
            <circle cx="80" cy="80" r="70" stroke="currentColor" strokeWidth="12" fill="transparent"
              strokeDasharray="8 6"
              className="text-slate-600"
            />
          )}
        </svg>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 flex flex-col items-center">
          <span className="text-5xl font-black text-white">{isWafBlocked ? 'N/A' : score}</span>
        </div>
      </div>
      <div className="mt-6">
        <div className="text-sm font-bold uppercase tracking-widest text-slate-400">Risk Meter</div>
        <div className={`text-2xl font-black mt-1 ${isWafBlocked ? 'text-slate-400' : score >= 80 ? 'text-emerald-400' : score >= 60 ? 'text-amber-400' : 'text-red-400'}`}>
          {isWafBlocked ? 'Blocked' : score >= 90 ? 'Excellent' : score >= 80 ? 'Good' : score >= 50 ? 'Fair' : 'Poor'}
        </div>
      </div>
    </div>
  );
};

export default ScoreDisplay;
