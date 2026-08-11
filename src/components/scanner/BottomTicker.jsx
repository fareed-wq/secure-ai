import React from 'react';
import { motion } from 'framer-motion';

const QUOTES = [
  "Scan your website for security risks",
  "Find weaknesses before attackers do",
  "Check your security in seconds",
  "Get clear, actionable recommendations",
  "Scan your website for security risks",
  "Find weaknesses before attackers do",
  "Check your security in seconds",
  "Get clear, actionable recommendations"
];

const BottomTicker = () => {
  return (
    <div className="relative flex overflow-x-hidden mt-0 pt-4 pb-2" style={{ WebkitMaskImage: 'linear-gradient(to right, transparent, black 10%, black 90%, transparent)', maskImage: 'linear-gradient(to right, transparent, black 10%, black 90%, transparent)' }}>
      <motion.div
        className="flex whitespace-nowrap gap-12 items-center text-slate-400 font-medium text-sm md:text-base pr-12"
        animate={{ x: ["0%", "-50%"] }}
        transition={{
          repeat: Infinity,
          ease: "linear",
          duration: 25,
        }}
      >
        {QUOTES.map((quote, idx) => (
          <span key={idx} className="flex-shrink-0">
            {quote}
          </span>
        ))}
      </motion.div>
    </div>
  );
};

export default BottomTicker;
