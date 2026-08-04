import React from 'react';
import { motion } from 'framer-motion';

const QUOTES = [
  "Detect 100,000+ security risks in minutes",
  "Trusted by security professionals",
  "Instant website security assessment",
  "No installation required",
  "OWASP-based security analysis",
  "SSL/TLS & Security Header Analysis",
  "Actionable remediation guidance",
  "Fast • Secure • Reliable",
  "Built for developers and business owners",
  "Professional security reports"
];

const QuotesTicker = () => {
  // We duplicate the array to create a seamless infinite loop
  const duplicatedQuotes = [...QUOTES, ...QUOTES];

  return (
    <div 
      className="relative flex overflow-hidden py-4 my-8 group" 
      style={{ 
        WebkitMaskImage: 'linear-gradient(to right, transparent, black 15%, black 85%, transparent)', 
        maskImage: 'linear-gradient(to right, transparent, black 15%, black 85%, transparent)' 
      }}
    >
      <motion.div
        className="flex whitespace-nowrap gap-6 items-center px-6"
        animate={{ x: ["0%", "-50%"] }}
        transition={{
          repeat: Infinity,
          ease: "linear",
          duration: 40,
        }}
        whileHover={{ animationPlayState: "paused" }} // This leverages Framer Motion's ability, but for pure CSS we'd use a class. Framer Motion doesn't natively support pausing via whileHover on 'animate'. It's better to use CSS animation for hover-pause.
      >
        {duplicatedQuotes.map((quote, idx) => (
          <div 
            key={idx} 
            className="flex-shrink-0 bg-slate-900/80 border border-slate-700/50 shadow-[0_0_15px_rgba(99,102,241,0.1)] text-slate-300 px-6 py-2.5 rounded-full font-medium text-sm transition-all duration-300 hover:border-indigo-500/50 hover:shadow-[0_0_20px_rgba(99,102,241,0.2)] hover:text-white hover:-translate-y-0.5 cursor-default"
          >
            {quote}
          </div>
        ))}
      </motion.div>
    </div>
  );
};

export default QuotesTicker;
