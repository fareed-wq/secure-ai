import React, { createContext, useContext, useEffect, useState } from 'react';
import { supabase } from '../lib/supabase';

const AuthContext = createContext({});

export const useAuth = () => useContext(AuthContext);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isRecovery, setIsRecovery] = useState(false);
  const [isRecoveryValidating, setIsRecoveryValidating] = useState(true);

  useEffect(() => {
    // Check active sessions and sets the user
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      setUser(session?.user ?? null);
      setLoading(false);

      // Determine if we are actively in a recovery callback flow
      const url = window.location.href;
      const isCallback = url.includes('code=') || url.includes('access_token=') || url.includes('error=') || url.includes('error_description=');

      if (!isCallback) {
        setIsRecoveryValidating(false);
      }
    }).catch(() => {
      setLoading(false);
      setIsRecoveryValidating(false);
    });

    // Listen for changes on auth state (logged in, signed out, etc.)
    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, session) => {
      if (event === 'PASSWORD_RECOVERY') {
        setIsRecovery(true);
        setIsRecoveryValidating(false);
      } else if (event === 'SIGNED_OUT') {
        setIsRecovery(false);
      }
      setSession(session);
      setUser(session?.user ?? null);
      setLoading(false);
    });

    return () => subscription.unsubscribe();
  }, []);

  const value = {
    session,
    user,
    isRecovery,
    setIsRecovery,
    isRecoveryValidating,
    setIsRecoveryValidating,
    signOut: () => supabase.auth.signOut(),
  };

  return (
    <AuthContext.Provider value={value}>
      {!loading && children}
    </AuthContext.Provider>
  );
};
