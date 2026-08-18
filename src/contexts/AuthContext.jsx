import React, { createContext, useContext, useEffect, useState } from 'react';
import { supabase, checkInitialRecovery } from '../lib/supabase';

const AuthContext = createContext({});

export const useAuth = () => useContext(AuthContext);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isRecovery, setIsRecovery] = useState(checkInitialRecovery);
  const [isRecoveryValidating, setIsRecoveryValidating] = useState(true);

  useEffect(() => {
    // Check active sessions and sets the user
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      setUser(session?.user ?? null);
      setLoading(false);
    }).catch(() => {
      setLoading(false);
    });

    // Definitive completion check: getUser() waits for background auth initialization
    // (including PKCE/URL token exchange) to complete before resolving.
    supabase.auth.getUser().finally(() => {
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
    signOut: () => supabase.auth.signOut(),
  };

  return (
    <AuthContext.Provider value={value}>
      {!loading && children}
    </AuthContext.Provider>
  );
};
