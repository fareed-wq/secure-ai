import React from 'react';
import { Check, X } from 'lucide-react';
import { validatePassword } from '../../lib/utils/passwordPolicy';

export const PasswordChecklist = ({ password, confirmPassword, showConfirm }) => {
  const { results } = validatePassword(password);
  const isEmpty = !password;
  const isConfirmEmpty = !confirmPassword;
  const confirmMatch = password && confirmPassword && password === confirmPassword;

  return (
    <div className="mt-2 space-y-1.5 text-xs">
      {results.map((req) => (
        <div key={req.id} className={`flex items-center gap-2 ${isEmpty ? 'text-slate-500' : (req.met ? 'text-emerald-500' : 'text-slate-400')}`}>
          {req.met && !isEmpty ? <Check className="w-3.5 h-3.5" /> : <X className="w-3.5 h-3.5" />}
          <span>{req.text}</span>
        </div>
      ))}
      {showConfirm && (
        <div className={`flex items-center gap-2 ${isConfirmEmpty ? 'text-slate-500' : (confirmMatch ? 'text-emerald-500' : 'text-rose-500')}`}>
          {confirmMatch && !isConfirmEmpty ? <Check className="w-3.5 h-3.5" /> : <X className="w-3.5 h-3.5" />}
          <span>Passwords must match</span>
        </div>
      )}
    </div>
  );
};
