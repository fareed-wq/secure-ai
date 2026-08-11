import React, { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';

const ScoreDisplay = ({ score, isWafBlocked, penalties, severityCounts }) => {
  const [showMethodology, setShowMethodology] = useState(false);
  
  // Calculate deductions based on actual backend penalties to match the final score
  const highDeduction = (penalties?.Critical || 0) + (penalties?.High || 0);
  const medDeduction = penalties?.Medium || 0;
  const lowDeduction = penalties?.Low || 0;
  const highCount = (severityCounts?.Critical || 0) + (severityCounts?.High || 0);
  const medCount = severityCounts?.Medium || 0;
  const lowCount = severityCounts?.Low || 0;
  
  const hasDeductions = highDeduction > 0 || medDeduction > 0 || lowDeduction > 0;

  return (
    <div className="bg-slate-900 border border-slate-800 p-8 rounded-3xl shadow-xl flex flex-col items-center justify-between text-center w-full h-full">
      <div className="flex flex-col items-center justify-center flex-grow">
        <div className="relative">
          <svg className="w-40 h-40 transform -rotate-90">
            <circle cx="80" cy="80" r="70" stroke="currentColor" strokeWidth="12" fill="transparent" className="text-slate-800" />
            {!isWafBlocked && (
              <circle cx="80" cy="80" r="70" stroke="currentColor" strokeWidth="12" fill="transparent"
                strokeDasharray={2 * Math.PI * 70}
                strokeDashoffset={2 * Math.PI * 70 * (1 - score / 100)}
                className={
                  score >= 90 ? 'text-emerald-500' :
                  score >= 80 ? 'text-teal-500' :
                  score >= 70 ? 'text-amber-500' :
                  score >= 60 ? 'text-orange-500' : 'text-rose-500'
                }
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
          <div className={`text-2xl font-black mt-1 ${
            isWafBlocked ? 'text-slate-400' : 
            score >= 90 ? 'text-emerald-400' : 
            score >= 80 ? 'text-teal-400' : 
            score >= 70 ? 'text-amber-400' : 
            score >= 60 ? 'text-orange-400' : 'text-rose-400'
          }`}>
            {isWafBlocked ? 'Blocked' : score >= 90 ? 'Excellent' : score >= 80 ? 'Good' : score >= 70 ? 'Needs Improvement' : score >= 60 ? 'Weak' : 'Critical'}
          </div>
        </div>
      </div>

      {!isWafBlocked && (
        <div className="w-full max-w-sm mt-4 text-left">
          <details className="group">
            <summary className="flex items-center justify-between w-full text-xs font-medium text-slate-400 hover:text-slate-300 transition-colors cursor-pointer list-none [&::-webkit-details-marker]:hidden">
              <span>{hasDeductions ? 'Why this score? · Score methodology' : 'Score methodology'}</span>
              <span className="group-open:rotate-180 transition-transform"><ChevronDown size={14} /></span>
            </summary>
            
            <div className="mt-4 space-y-4">
              {hasDeductions && (
                <div className="bg-slate-950/50 p-4 rounded-xl border border-slate-800/50">
                  <div className="text-slate-300 font-bold mb-3">Why?</div>
                  <div className="space-y-2 text-sm">
                    {highCount > 0 && (
                      <div className="flex justify-between text-rose-400">
                        <span>{highCount} High-risk {highCount === 1 ? 'issue' : 'issues'}</span>
                        <span>-{highDeduction}</span>
                      </div>
                    )}
                    {medCount > 0 && (
                      <div className="flex justify-between text-amber-400">
                        <span>{medCount} Medium-risk {medCount === 1 ? 'issue' : 'issues'}</span>
                        <span>-{medDeduction}</span>
                      </div>
                    )}
                    {lowCount > 0 && (
                      <div className="flex justify-between text-slate-400">
                        <span>{lowCount} Low-risk {lowCount === 1 ? 'issue' : 'issues'}</span>
                        <span>-{lowDeduction}</span>
                      </div>
                    )}
                    <div className="border-t border-slate-800 my-2 pt-2 flex justify-between font-semibold text-slate-300">
                      <span>Total deductions</span>
                      <span>-{highDeduction + medDeduction + lowDeduction}</span>
                    </div>
                    <div className="mt-3 pt-3 flex justify-between items-center font-black text-white text-base">
                      <span>Final Score</span>
                      <span className="text-xl">{score}<span className="text-sm text-slate-400 font-normal">/100</span></span>
                    </div>
                  </div>
                </div>
              )}
              
              <div className="text-xs text-slate-500 bg-slate-800/30 p-3 rounded-lg border border-slate-800/50 leading-relaxed">
                <div className="font-bold text-slate-400 mb-1">Score Methodology</div>
                The score starts at 100. Points are deducted based on finding severity: High-risk issues deduct up to 15 points each, Medium-risk up to 10 points, and Low-risk up to 5 points. Deductions are capped per category to prevent a single issue type from disproportionately tanking the score.
              </div>
            </div>
          </details>
        </div>
      )}
    </div>
  );
};

export default ScoreDisplay;
