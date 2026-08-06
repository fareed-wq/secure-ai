import React, { useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Sparkles, X } from 'lucide-react';

const PdfComingSoonModal = ({ isOpen, onClose }) => {
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              onClick={(e) => e.stopPropagation()}
              className="bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl w-full max-w-md overflow-hidden relative"
            >
              <button 
                onClick={onClose}
                className="absolute top-4 right-4 text-slate-500 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>

              <div className="p-8 text-center flex flex-col items-center">
                <div className="w-16 h-16 bg-indigo-950 text-indigo-400 border border-indigo-800 rounded-full flex items-center justify-center mb-6 shadow-lg shadow-indigo-900/20">
                  <Sparkles className="w-8 h-8" />
                </div>
                
                <div className="mb-2">
                  <span className="bg-indigo-600/30 text-indigo-300 border border-indigo-500/40 text-xs px-2.5 py-0.5 rounded-full font-semibold">
                    COMING SOON
                  </span>
                </div>
                
                <h3 className="text-xl font-bold text-white mb-3">PDF Export — Work in Progress</h3>
                <p className="text-sm text-slate-300 leading-relaxed mb-8">
                  We are calibrating multi-page audit report downloads with full compliance mappings. This feature will be available shortly!
                </p>
                
                <button 
                  onClick={onClose}
                  className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-5 py-3 rounded-xl text-sm transition shadow-lg shadow-indigo-500/25"
                >
                  Got It
                </button>
              </div>
            </motion.div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
};

export default PdfComingSoonModal;
