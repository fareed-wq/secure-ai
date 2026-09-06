import { normalizeScanResult } from '../models/scanResult';

export const API_BASE_URL = import.meta.env.VITE_API_URL
  || (import.meta.env.DEV ? 'http://localhost:5000' : '');

import { supabase } from '../supabase';

class ScanApiClient {
  async getAuthHeader() {
    const { data: { session } } = await supabase.auth.getSession();
    return session?.access_token ? { 'Authorization': `Bearer ${session.access_token}` } : {};
  }

  async runScan(url, scanMode = 'passive', reportMode = 'simple') {
    const minWait = new Promise(resolve => setTimeout(resolve, 6000));

    const headers = {
      'Content-Type': 'application/json',
      ...(await this.getAuthHeader())
    };

    const fetchPromise = fetch(`${API_BASE_URL}/api/scan`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ url, scan_mode: scanMode, report_mode: reportMode }),
    });

    const [response] = await Promise.all([fetchPromise, minWait]);
    const data = await response.json();

    if (data.error) throw new Error(data.error);
    return normalizeScanResult(data);
  }


  async compareScans(scan1Id, scan2Id) {
    const headers = await this.getAuthHeader();
    const response = await fetch(`${API_BASE_URL}/api/scans/compare?scan_id_1=${scan1Id}&scan_id_2=${scan2Id}`, {
      headers
    });
    if (!response.ok) {
      let err;
      try { err = await response.json(); } catch(e){}
      throw new Error((err && err.detail) || err?.error || 'Failed to compare scans');
    }
    return await response.json();
  }

  async getQuota() {
    try {
      const headers = await this.getAuthHeader();
      const response = await fetch(`${API_BASE_URL}/api/quota`, { headers });
      if (!response.ok) return null;
      return await response.json();
    } catch (e) {
      console.error("Failed to fetch quota", e);
      return null;
    }
  }
}

export const scanApi = new ScanApiClient();
