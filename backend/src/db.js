import { Pool } from 'pg';

// Using environment variables for connection configuration
const pool = new Pool({
  user: process.env.PGUSER || 'postgres',
  host: process.env.PGHOST || 'localhost',
  database: process.env.PGDATABASE || 'secure_ai_db',
  password: process.env.PGPASSWORD || 'postgres',
  port: parseInt(process.env.PGPORT || '5432', 10),
});

export async function query(text, params) {
  const start = Date.now();
  const res = await pool.query(text, params);
  const duration = Date.now() - start;
  console.log('executed query', { text, duration, rows: res.rowCount });
  return res;
}

// Example function to execute a query within a specific tenant context
export async function queryAsTenant(tenantId, text, params) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        // Set the session variable for RLS
        await client.query(`SET LOCAL app.current_tenant_id = $1`, [tenantId]);
        
        const res = await client.query(text, params);
        
        await client.query('COMMIT');
        return res;
    } catch (e) {
        await client.query('ROLLBACK');
        throw e;
    } finally {
        client.release();
    }
}
