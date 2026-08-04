import React from 'react';
import { MessageCircle } from 'lucide-react';

const WhatsAppCTA = () => {
  return (
    <div className="mt-12 flex flex-col items-center text-center space-y-4 max-w-lg mx-auto">
      <div className="space-y-1">
        <h3 className="text-xl font-bold text-slate-200">
          Need help understanding your security report?
        </h3>
        <p className="text-sm text-slate-400">
          Our cybersecurity experts are available to help you understand the results and improve your website's security.
        </p>
      </div>
      
      <a 
        href="https://wa.me/1234567890" 
        target="_blank" 
        rel="noopener noreferrer"
        className="group relative inline-flex items-center gap-3 bg-[#25D366] hover:bg-[#1ebd5a] text-white px-8 py-3.5 rounded-xl font-bold transition-all transform hover:scale-[1.02] active:scale-[0.98] shadow-lg shadow-[#25D366]/20 overflow-hidden"
      >
        <div className="absolute inset-0 bg-white/20 translate-y-full group-hover:translate-y-0 transition-transform duration-300 ease-out"></div>
        <MessageCircle className="w-5 h-5 relative z-10" />
        <span className="relative z-10">Chat with us on WhatsApp</span>
      </a>
    </div>
  );
};

export default WhatsAppCTA;
