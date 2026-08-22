import { supabase } from '../supabase';

const adminFetch = async (endpoint) => {
  const { data: { session } } = await supabase.auth.getSession();
  
  if (!session?.access_token) {
    const error = new Error('No active session');
    error.status = 401;
    throw error;
  }

  const response = await fetch(`/api/admin${endpoint}`, {
    headers: {
      'Authorization': `Bearer ${session.access_token}`,
      'Content-Type': 'application/json'
    }
  });

  if (response.status === 401 || response.status === 403) {
    const error = new Error(`Access Denied (HTTP ${response.status})`);
    error.status = response.status;
    throw error;
  }

  if (!response.ok) {
    throw new Error(`API Error: ${response.status}`);
  }

  return response.json();
};

export const adminApi = {
  getMe: () => adminFetch('/me'),
  getOverview: () => adminFetch('/overview'),
  getUsers: (limit = 50, offset = 0) => adminFetch(`/users?limit=${limit}&offset=${offset}`),
  getUserDetail: (userId) => adminFetch(`/users/${userId}`),
  getScans: (limit = 50, offset = 0) => adminFetch(`/scans?limit=${limit}&offset=${offset}`),
  getAuditLogs: (limit = 50, offset = 0) => adminFetch(`/audit-logs?limit=${limit}&offset=${offset}`)
};
