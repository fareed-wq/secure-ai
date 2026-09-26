-- Migration: Add explicit Data API grants for public tables
-- Fixes missing grants before Supabase enforces explicit privileges on October 30, 2026

-- 1. Grant full access to service_role (bypasses RLS anyway, but needs Data API grants under new rules)
GRANT ALL ON public.profiles TO service_role;
GRANT ALL ON public.scans TO service_role;
GRANT ALL ON public.user_roles TO service_role;
GRANT ALL ON public.audit_logs TO service_role;
GRANT ALL ON public.scan_shares TO service_role;
GRANT ALL ON public.user_plans TO service_role;
GRANT ALL ON public.scan_schedules TO service_role;
GRANT ALL ON public.scheduled_scan_runs TO service_role;
GRANT ALL ON public.cpe_cve_cache TO service_role;

-- 2. Grant exact scoped CRUD to authenticated role (based on what RLS policies allow)
GRANT SELECT, UPDATE ON public.profiles TO authenticated;
GRANT SELECT, INSERT, DELETE ON public.scans TO authenticated;
GRANT SELECT, INSERT ON public.scan_shares TO authenticated;
GRANT SELECT ON public.scan_schedules TO authenticated;
GRANT SELECT ON public.scheduled_scan_runs TO authenticated;

-- (No grants provided to anon; user_roles, audit_logs, user_plans, and cpe_cve_cache fully denied to authenticated)
