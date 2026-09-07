import React from 'react';

const RadarLoader = () => {
  return (
    <div className="relative flex flex-col items-center justify-center">
      {/* Radar Container */}
      <div
        className="relative flex items-center justify-center rounded-full border border-indigo-500/30 bg-slate-900/50 shadow-[0_0_20px_rgba(99,102,241,0.15)]"
        style={{ width: '120px', height: '120px' }}
        aria-hidden="true"
      >
        {/* Middle Ring - dashed */}
        <div className="absolute inset-[15%] border border-dashed border-indigo-400/30 rounded-full"></div>

        {/* Inner Ring */}
        <div className="absolute inset-[35%] border border-indigo-400/20 rounded-full"></div>

        {/* Center Point */}
        <div className="absolute w-2 h-2 bg-indigo-400 rounded-full shadow-[0_0_8px_rgba(129,140,248,0.8)]"></div>

        {/* Rotating Sweep */}
        <div className="absolute inset-0 rounded-full overflow-hidden animate-[spin_2s_linear_infinite] motion-reduce:animate-none">
          {/* Conic gradient for the sweep glow */}
          <div
            className="absolute inset-0"
            style={{
              background: 'conic-gradient(from 0deg, transparent 60%, rgba(99, 102, 241, 0.05) 80%, rgba(45, 212, 191, 0.4) 100%)',
            }}
          ></div>
          {/* The beam line (teal-ish to match cyan/indigo theme) */}
          <div className="absolute top-0 left-1/2 w-0.5 h-1/2 bg-teal-400/80 shadow-[0_0_8px_rgba(45,212,191,0.8)] origin-bottom -ml-[1px]"></div>
        </div>
      </div>
    </div>
  );
};

export default RadarLoader;
