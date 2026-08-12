import React, { useState } from 'react';
import { REMEDIATION_SNIPPETS } from '../../lib/remediationSnippets';

export const RemediationSnippetBox = ({ findingName }) => {
  const snippets = REMEDIATION_SNIPPETS[findingName];
  const [activeTab, setActiveTab] = useState(0);
  const [copied, setCopied] = useState(false);

  if (!snippets || snippets.length === 0) return null;

  const currentSnippet = snippets[activeTab];

  const handleCopy = () => {
    navigator.clipboard.writeText(currentSnippet.code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="mt-4 rounded-lg border border-slate-700 bg-slate-900/80 p-4">
      <div className="mb-3 flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          🛠️ Quick Fix Snippets
        </span>
        <button
          onClick={handleCopy}
          className="rounded bg-indigo-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-indigo-500 transition-colors"
        >
          {copied ? '✓ Copied!' : '📋 Copy Code'}
        </button>
      </div>

      {/* Platform Tabs */}
      <div className="mb-3 flex flex-wrap gap-2 border-b border-slate-800 pb-2">
        {snippets.map((item, index) => (
          <button
            key={item.platform}
            onClick={() => setActiveTab(index)}
            className={`rounded px-3 py-1 text-xs font-medium transition-colors ${
              activeTab === index
                ? 'bg-slate-700 text-cyan-400'
                : 'text-slate-400 hover:bg-slate-800 hover:text-slate-50'
            }`}
          >
            {item.platform}
          </button>
        ))}
      </div>

      {/* Code Display */}
      <pre className="overflow-x-auto rounded bg-slate-950 p-3 text-xs font-mono text-emerald-400 border border-slate-800/80">
        <code>{currentSnippet.code}</code>
      </pre>

      {currentSnippet.notes && (
        <p className="mt-2 text-[11px] text-slate-400 italic">
          💡 {currentSnippet.notes}
        </p>
      )}
    </div>
  );
};
