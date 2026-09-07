import React from 'react';
import { ArrowLeft } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';

const BackButton = ({ to, onClick, children, className = '' }) => {
  const navigate = useNavigate();

  const baseClasses = "inline-flex items-center gap-2 text-slate-400 hover:text-slate-200 transition-colors bg-slate-900 border border-slate-700 hover:border-slate-500 px-4 py-2 rounded-lg text-sm font-semibold focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent";
  const combinedClasses = `${baseClasses} ${className}`.trim();

  const content = (
    <>
      <ArrowLeft className="w-4 h-4 shrink-0" aria-hidden="true" />
      <span>{children}</span>
    </>
  );

  if (to) {
    return (
      <Link to={to} className={combinedClasses} aria-label={typeof children === 'string' ? children : 'Go back'}>
        {content}
      </Link>
    );
  }

  return (
    <button
      type="button"
      onClick={onClick || (() => navigate(-1))}
      className={combinedClasses}
      aria-label={typeof children === 'string' ? children : 'Go back'}
    >
      {content}
    </button>
  );
};

export default BackButton;
