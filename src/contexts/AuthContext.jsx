import React, { createContext, useContext, useEffect, useState } from 'react';
import { supabase, checkInitialRecovery } from '../lib/supabase';

const AuthContext = createContext({});

export const useAuth = () => useContext(AuthContext);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isAdmin, setIsAdmin] = useState(false);
  const [isAdminLoading, setIsAdminLoading] = useState(true);
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
      // Supabase internally emits PASSWORD_RECOVERY inside a setTimeout(0).
      // We push validation completion to the macro-task queue to guarantee it
      // executes strictly after the recovery event has fired.
      setTimeout(() => {
        setIsRecoveryValidating(false);
      }, 0);
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

  useEffect(() => {
        const checkAdmin = async () => {
      if (!session?.access_token) {
        setIsAdmin(false);
        setIsAdminLoading(false);
        return;
      }
      setIsAdminLoading(true);
      try {
        const response = await fetch('/api/admin/me', {
          headers: { 'Authorization': `Bearer ${session.access_token}` }
        });

        if (response.ok) {
          const data = await response.json();
          setIsAdmin(data.role === 'admin');
        } else if (response.status === 403) {
          // Expected non-admin result
          setIsAdmin(false);
        } else if (response.status === 401) {
          // Unauthorized, let session listener handle sign out if token is dead
          setIsAdmin(false);
        } else {
          // Genuine failure or unexpected status
          console.error(`Unexpected admin check error: HTTP ${response.status}`);
          setIsAdmin(false);
        }
      } catch (e) {
        console.error('Network error checking admin status:', e);
        setIsAdmin(false);
      } finally {
        setIsAdminLoading(false);
      }
    };
    checkAdmin();
  }, [session?.access_token]);

  const value = {
    session,
    user,
    isAdmin,
    isRecovery,
    setIsRecovery,
    isRecoveryValidating, loading,
    signOut: () => supabase.auth.signOut(),
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
