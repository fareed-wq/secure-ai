import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { query, queryAsTenant } from './db.js';

dotenv.config();

const app = express();
const port = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

// Basic health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Example route: Get findings for a tenant (simulates RLS in action)
app.get('/api/findings', async (req, res) => {
    // In a real app, the tenant_id would come from the authenticated user's JWT token
    const tenantId = req.headers['x-tenant-id']; 
    
    if (!tenantId) {
        return res.status(401).json({ error: 'Missing x-tenant-id header' });
    }

    try {
        // This query does NOT have a WHERE clause for tenant_id. 
        // Row Level Security (RLS) in Postgres will automatically filter the results
        // based on the app.current_tenant_id set in queryAsTenant!
        const result = await queryAsTenant(tenantId, 'SELECT * FROM findings ORDER BY discovered_at DESC LIMIT 50');
        res.json({ data: result.rows });
    } catch (error) {
        console.error('Error fetching findings:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Mock endpoint to simulate receiving a scan report
app.post('/api/scans', async (req, res) => {
    const { target } = req.body;
    if (!target) {
        return res.status(400).json({ error: 'Target URL is required' });
    }
    
    // As per safety guidelines, this endpoint only simulates the orchestration.
    // It does NOT execute any actual scanning tools.
    res.json({ 
        message: 'Scan job successfully queued (Simulated).', 
        jobId: 'simulated-job-' + Date.now(),
        target: target 
    });
});

app.listen(port, () => {
  console.log(`Secure-AI Backend listening on port ${port}`);
});
