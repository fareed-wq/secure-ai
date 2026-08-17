import { createClient } from '@supabase/supabase-js';

// Initialize Supabase client
// Note: In a real Vercel deployment, these will be injected via environment variables.
// For the MVP, if these are missing, we fall back to dummy values to prevent crashes,
// but authentication will not work until real credentials are provided.

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseAnonKey) {
  console.error("Missing Supabase configuration. Please set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY in your .env.local file.");
}

export const supabase = createClient(
  supabaseUrl || '',
  supabaseAnonKey || ''
);
