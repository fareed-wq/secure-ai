import { normalizeScanResult } from '../models/scanResult';

export const API_BASE_URL = 
  (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') 
    ? (import.meta.env.VITE_API_URL || 'http://localhost:5000') 
    : '';

class ScanApiClient {
  /**
   * Submits a URL to the backend scanner API.
   * 
   * @param {string} url - The URL to scan.
   * @returns {Promise<Object>} - The raw scan report data or throws an error.
   */
  async runScan(url) {
    const minWait = new Promise(resolve => setTimeout(resolve, 6000));
    
    const fetchPromise = fetch(`${API_BASE_URL}/api/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url }),
    });

    // Wait for at least 6 seconds and for the fetch to complete
    const [response] = await Promise.all([fetchPromise, minWait]);
    
    const data = await response.json();
    
    if (data.error) {
      throw new Error(data.error);
    }
    
    return normalizeScanResult(data);
  }
}

export const scanApi = new ScanApiClient();
