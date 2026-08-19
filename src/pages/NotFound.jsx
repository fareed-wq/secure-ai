import React from 'react';
import { Link } from 'react-router-dom';
import { FileQuestion, ArrowLeft } from 'lucide-react';

const NotFound = () => {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] text-center px-4">
      <div className="w-20 h-20 bg-slate-900 rounded-full flex items-center justify-center mb-6 border border-slate-800">
        <FileQuestion size={40} className="text-slate-500" />
      </div>
      <h1 className="text-4xl font-bold text-slate-50 mb-3">Page Not Found</h1>
      <p className="text-slate-400 max-w-md mb-8">
        We couldn't find the page you're looking for. It might have been removed, renamed, or didn't exist in the first place.
      </p>
      <Link
        to="/"
        className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white px-6 py-3 rounded-lg font-medium transition-colors"
      >
        <ArrowLeft size={18} />
        Return Home
      </Link>
    </div>
  );
};

export default NotFound;
