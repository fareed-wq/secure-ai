def patch_file():
    with open('src/components/scanner/ReportHeader.jsx', 'r') as f:
        content = f.read()

    # Add State
    content = content.replace("import React from 'react';", "import React, { useState } from 'react';")
    content = content.replace("const findings = reportData?.findings || [];", "const [shareStatus, setShareStatus] = useState('idle');\n  const [shareToken, setShareToken] = useState(null);\n  const [showShareModal, setShowShareModal] = useState(false);\n  const [shareError, setShareError] = useState(null);\n\n  const findings = reportData?.findings || [];")
    
    # Add handleShareClick
    handle_share = """
  const handleShareClick = async () => {
    if (!onRequireAuth) return;
    
    // First save the scan if it hasn't been saved yet
    let scanId = savedScanId;
    if (!scanId) {
      setShareStatus('saving');
      setShowShareModal(true);
      scanId = await onSaveScan();
      if (!scanId) {
        setShareError('Failed to save scan before sharing.');
        setShareStatus('error');
        return;
      }
    }

    setShareStatus('generating');
    setShowShareModal(true);
    setShareError(null);
    
    try {
      const response = await fetch('/api/share/create', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${(await supabase.auth.getSession()).data.session?.access_token}`
        },
        body: JSON.stringify({ scan_id: scanId })
      });
      
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Failed to create share link');
      
      setShareToken(data.share_token);
      setShareStatus('ready');
    } catch (err) {
      setShareError(err.message);
      setShareStatus('error');
    }
  };

  const handleCopyLink = () => {
    navigator.clipboard.writeText(`${window.location.origin}/shared/${shareToken}`);
    setShareStatus('copied');
    setTimeout(() => {
        if (showShareModal) setShareStatus('ready');
    }, 2000);
  };

  const handleRevokeShare = async () => {
    setShareStatus('revoking');
    try {
      const response = await fetch('/api/share/revoke', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${(await supabase.auth.getSession()).data.session?.access_token}`
        },
        body: JSON.stringify({ share_token: shareToken })
      });
      
      if (!response.ok) throw new Error('Failed to revoke');
      
      setShareStatus('revoked');
      setTimeout(() => setShowShareModal(false), 2000);
    } catch (err) {
      setShareError(err.message);
      setShareStatus('error');
    }
  };
"""
    content = content.replace("const findings = reportData?.findings || [];", handle_share + "\n  const findings = reportData?.findings || [];")
    
    # Needs supabase import
    content = content.replace("import { Globe, Download, Bookmark, Share2 } from 'lucide-react';", "import { Globe, Download, Bookmark, Share2, Link as LinkIcon, X } from 'lucide-react';\nimport { supabase } from '../../lib/api/supabase';")
    
    # Add Share2 button next to Bookmark
    button_html = """          <button
            onClick={handleShareClick}
            title="Share Public Link"
            className="p-2.5 bg-slate-800 hover:bg-slate-700 text-slate-50 rounded-lg transition-colors border border-slate-700"
          >
            <Share2 className="w-4 h-4" />
          </button>"""
    
    content = content.replace("<Bookmark className=\"w-4 h-4\" />\n          </button>", "<Bookmark className=\"w-4 h-4\" />\n          </button>\n" + button_html)
    
    # Add Modal HTML at the end of the div
    modal_html = """
      {/* Share Modal */}
      {showShareModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4 print:hidden">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl w-full max-w-md overflow-hidden animate-in fade-in zoom-in duration-200">
            <div className="flex items-center justify-between p-4 border-b border-slate-800">
              <h3 className="font-bold text-lg text-slate-50 flex items-center gap-2">
                <Share2 className="w-5 h-5 text-indigo-400" />
                Share Report
              </h3>
              <button onClick={() => setShowShareModal(false)} className="text-slate-400 hover:text-slate-200 p-1 rounded-lg hover:bg-slate-800 transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6">
              {shareStatus === 'saving' && (
                <div className="text-center py-4 text-slate-400 animate-pulse">Saving scan to dashboard...</div>
              )}
              {shareStatus === 'generating' && (
                <div className="text-center py-4 text-slate-400 animate-pulse">Generating secure link...</div>
              )}
              {shareStatus === 'revoking' && (
                <div className="text-center py-4 text-rose-400 animate-pulse">Revoking link...</div>
              )}
              {shareStatus === 'revoked' && (
                <div className="text-center py-4 text-rose-400 font-medium">Link has been revoked.</div>
              )}
              {shareStatus === 'error' && (
                <div className="text-center py-4 text-rose-400 font-medium">Error: {shareError}</div>
              )}
              {(shareStatus === 'ready' || shareStatus === 'copied') && shareToken && (
                <div className="space-y-4">
                  <p className="text-sm text-slate-300">Anyone with this link can view this report.</p>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 font-mono text-sm text-slate-400 truncate select-all">
                      {window.location.origin}/shared/{shareToken}
                    </div>
                    <button 
                      onClick={handleCopyLink}
                      className={`px-4 py-3 rounded-xl font-bold transition-all whitespace-nowrap flex items-center gap-2 ${
                        shareStatus === 'copied' 
                          ? 'bg-emerald-500/20 text-emerald-400' 
                          : 'bg-indigo-600 hover:bg-indigo-500 text-white'
                      }`}
                    >
                      <LinkIcon className="w-4 h-4" />
                      {shareStatus === 'copied' ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                  <div className="pt-4 border-t border-slate-800/50 mt-6 flex justify-end">
                     <button onClick={handleRevokeShare} className="text-sm text-rose-400 hover:text-rose-300 transition-colors font-medium">
                        Revoke Link
                     </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
"""
    
    content = content.replace("    </div>\n  );\n};", modal_html + "\n    </div>\n  );\n};")
    
    # Fix props
    content = content.replace("onSaveScan, saveStatus,", "onSaveScan, savedScanId, saveStatus,")
    
    with open('src/components/scanner/ReportHeader.jsx', 'w') as f:
        f.write(content)

patch_file()
