-- Supabase Migration: Guest and Admin Security
-- Description: Adds user_roles and audit_logs tables, is_admin helper, and updates RLS.

-- 1. user_roles table
CREATE TABLE IF NOT EXISTS public.user_roles (
    user_id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('user', 'admin')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;

-- Explicitly deny normal users access to user_roles
CREATE POLICY "Deny SELECT to user_roles for normal users" ON public.user_roles FOR SELECT TO authenticated USING (false);
CREATE POLICY "Deny INSERT to user_roles for normal users" ON public.user_roles FOR INSERT TO authenticated WITH CHECK (false);
CREATE POLICY "Deny UPDATE to user_roles for normal users" ON public.user_roles FOR UPDATE TO authenticated USING (false) WITH CHECK (false);
CREATE POLICY "Deny DELETE to user_roles for normal users" ON public.user_roles FOR DELETE TO authenticated USING (false);

-- 2. is_admin() helper
-- Uses auth.uid() directly to prevent arbitrary UUID probing.
-- Sets search_path to '' to prevent search-path injection.
-- Uses SECURITY DEFINER to bypass RLS on user_roles for the current user check.
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    is_adm boolean;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM public.user_roles
        WHERE user_roles.user_id = auth.uid()
        AND role = 'admin'
    ) INTO is_adm;
    RETURN is_adm;
END;
$$;

-- Restrict execution to authenticated users only, revoke from PUBLIC/anon.
REVOKE ALL ON FUNCTION public.is_admin() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.is_admin() FROM anon;
GRANT EXECUTE ON FUNCTION public.is_admin() TO authenticated;
GRANT EXECUTE ON FUNCTION public.is_admin() TO service_role;

-- 3. audit_logs table
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_user_id uuid REFERENCES auth.users(id),
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id text,
    before_state jsonb,
    after_state jsonb,
    reason text,
    created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- Explicitly deny normal users access to audit_logs
CREATE POLICY "Deny SELECT to audit_logs for normal users" ON public.audit_logs FOR SELECT TO authenticated USING (false);
CREATE POLICY "Deny INSERT to audit_logs for normal users" ON public.audit_logs FOR INSERT TO authenticated WITH CHECK (false);
CREATE POLICY "Deny UPDATE to audit_logs for normal users" ON public.audit_logs FOR UPDATE TO authenticated USING (false) WITH CHECK (false);
CREATE POLICY "Deny DELETE to audit_logs for normal users" ON public.audit_logs FOR DELETE TO authenticated USING (false);

CREATE INDEX IF NOT EXISTS idx_audit_logs_admin_user_id ON public.audit_logs(admin_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON public.audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action_resource ON public.audit_logs(action, resource_type);

-- 4. Existing `scans` RLS Audit and Update
-- Only adding SELECT policy for Admins. We do NOT change INSERT/UPDATE/DELETE.
-- We assume an existing policy allows users to SELECT their own scans. This policy supplements it.
CREATE POLICY "Admins can view all scans for support"
ON public.scans
FOR SELECT
TO authenticated
USING (public.is_admin());
