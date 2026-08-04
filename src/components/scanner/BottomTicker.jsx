import React from 'react';
import { motion } from 'framer-motion';

const QUOTES = [
  "Paste your link below to catch hidden security flaws before they break your site.",
  "Catch hidden website risks before they cause problems.",
  "Enter your domain to uncover hidden security risks automatically.",
  "Get a simple, easy-to-read safety report for your website instantly.",
  "Paste your link below to catch hidden security flaws before they break your site.",
  "Catch hidden website risks before they cause problems.",
  "Enter your domain to uncover hidden security risks automatically.",
  "Get a simple, easy-to-read safety report for your website instantly."
];

const BottomTicker = () => {
  return (
    <div className="relative flex overflow-x-hidden mt-8 pt-4 pb-2" style={{ WebkitMaskImage: 'linear-gradient(to right, transparent, black 10%, black 90%, transparent)', maskImage: 'linear-gradient(to right, transparent, black 10%, black 90%, transparent)' }}>
      <motion.div
        className="flex whitespace-nowrap gap-12 items-center text-slate-400 italic text-sm md:text-base pr-12"
        animate={{ x: ["0%", "-50%"] }}
        transition={{
          repeat: Infinity,
          ease: "linear",
          duration: 25,
        }}
      >
        {QUOTES.map((quote, idx) => (
          <span key={idx} className="flex-shrink-0">
            "{quote}"
          </span>
        ))}
      </motion.div>
    </div>
  );
};

export default BottomTicker;
