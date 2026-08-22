-- Migration: User Plans and Status (Suspension)
CREATE TABLE IF NOT EXISTS public.user_plans (
    user_id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    plan text NOT NULL CHECK (plan IN ('free', 'professional')),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.user_plans ENABLE ROW LEVEL SECURITY;

-- Explicitly deny normal users access to user_plans
CREATE POLICY "Deny SELECT to user_plans for normal users" ON public.user_plans FOR SELECT TO authenticated USING (false);
CREATE POLICY "Deny INSERT to user_plans for normal users" ON public.user_plans FOR INSERT TO authenticated WITH CHECK (false);
CREATE POLICY "Deny UPDATE to user_plans for normal users" ON public.user_plans FOR UPDATE TO authenticated USING (false) WITH CHECK (false);
CREATE POLICY "Deny DELETE to user_plans for normal users" ON public.user_plans FOR DELETE TO authenticated USING (false);
