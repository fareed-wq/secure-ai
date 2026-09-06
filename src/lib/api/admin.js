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

const adminPost = async (endpoint, payload = {}) => {
  const { data: { session } } = await supabase.auth.getSession();
  
  if (!session?.access_token) {
    const error = new Error('No active session');
    error.status = 401;
    throw error;
  }

  const response = await fetch(`/api/admin${endpoint}`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${session.access_token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });

  if (response.status === 401 || response.status === 403) {
    const error = new Error(`Access Denied (HTTP ${response.status})`);
    error.status = response.status;
    throw error;
  }

  if (!response.ok) {
    let errorMsg = `API Error: ${response.status}`;
    try {
      const errorData = await response.json();
      if (errorData.detail) errorMsg = errorData.detail;
    } catch (e) {}
    throw new Error(errorMsg);
  }

  return response.json();
};

export const adminApi = {
  getMe: () => adminFetch('/me'),
  getOverview: () => adminFetch('/overview'),
  getUsers: (limit = 50, offset = 0, search = '') => adminFetch(`/users?limit=${limit}&offset=${offset}${search ? `&search=${encodeURIComponent(search)}` : ''}`),
  getUserDetail: (userId) => adminFetch(`/users/${userId}`),
  getAuditLogs: (limit = 50, offset = 0, search = '') => adminFetch(`/audit-logs?limit=${limit}&offset=${offset}${search ? `&search=${encodeURIComponent(search)}` : ''}`),
  grantProfessional: (userId, reason) => adminPost(`/users/${userId}/grant-professional`, { reason }),
  removeProfessional: (userId, reason) => adminPost(`/users/${userId}/remove-professional`, { reason }),
  suspendUser: (userId, reason) => adminPost(`/users/${userId}/suspend`, { reason }),
  reactivateUser: (userId, reason) => adminPost(`/users/${userId}/reactivate`, { reason }),
  getUserQuota: (userId) => adminFetch(`/users/${userId}/quota`),
  resetQuota: (userId, reason) => adminPost(`/users/${userId}/reset-quota`, { reason }),
  compareScans: (scan1, scan2) => adminFetch(`/scans/compare?scan_id_1=${scan1}&scan_id_2=${scan2}`)
};
