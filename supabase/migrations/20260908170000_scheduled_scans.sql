-- Migration: Scheduled Scans
-- Description: Adds scan_schedules and scheduled_scan_runs tables with strict schema and RLS.

-- 1. scan_schedules table
CREATE TABLE IF NOT EXISTS public.scan_schedules (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    
    target_url text NOT NULL,
    normalized_target text NOT NULL,
    scan_mode text NOT NULL CHECK (scan_mode IN ('passive')),
    
    frequency text NOT NULL CHECK (frequency IN ('daily', 'weekly', 'monthly')),
    time_of_day time NOT NULL,
    timezone text NOT NULL,
    
    day_of_week smallint CHECK (day_of_week >= 0 AND day_of_week <= 6),
    day_of_month smallint CHECK (day_of_month >= 1 AND day_of_month <= 28),
    
    is_enabled boolean NOT NULL DEFAULT true,
    qstash_schedule_id text UNIQUE,
    authorization_acknowledged_at timestamptz NOT NULL,
    
    last_run_at timestamptz,
    last_status text NOT NULL DEFAULT 'never' CHECK (last_status IN ('never', 'queued', 'running', 'completed', 'failed', 'paused_entitlement')),
    last_scan_id uuid,
    last_error_code text,
    
    next_run_at timestamptz,
    worker_lease_until timestamptz,
    
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Cross-column checks for frequency constraints
ALTER TABLE public.scan_schedules ADD CONSTRAINT chk_frequency_daily 
    CHECK (frequency != 'daily' OR (day_of_week IS NULL AND day_of_month IS NULL));
ALTER TABLE public.scan_schedules ADD CONSTRAINT chk_frequency_weekly 
    CHECK (frequency != 'weekly' OR (day_of_week IS NOT NULL AND day_of_month IS NULL));
ALTER TABLE public.scan_schedules ADD CONSTRAINT chk_frequency_monthly 
    CHECK (frequency != 'monthly' OR (day_of_month IS NOT NULL AND day_of_week IS NULL));

-- Unique constraint to prevent exact duplicate schedules
CREATE UNIQUE INDEX idx_unique_schedule 
    ON public.scan_schedules (user_id, normalized_target, frequency, time_of_day, timezone, COALESCE(day_of_week, -1), COALESCE(day_of_month, -1));

ALTER TABLE public.scan_schedules ENABLE ROW LEVEL SECURITY;

-- Trigger to enforce maximum of 3 schedules per user
CREATE OR REPLACE FUNCTION check_max_schedules() RETURNS trigger 
SECURITY DEFINER SET search_path = public AS $$
BEGIN
    -- Transaction-scoped advisory lock keyed by user_id to prevent concurrent inserts racing the count
    PERFORM pg_advisory_xact_lock(hashtext(NEW.user_id::text));
    
    IF (SELECT count(*) FROM public.scan_schedules WHERE user_id = NEW.user_id) >= 3 THEN
        RAISE EXCEPTION 'Maximum of 3 scheduled scans reached.';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_max_schedules
    BEFORE INSERT ON public.scan_schedules
    FOR EACH ROW
    EXECUTE FUNCTION check_max_schedules();

-- RLS: Owners can view their schedules if they are admin (V1 rule)
CREATE POLICY "Users can view own schedules if admin" ON public.scan_schedules 
    FOR SELECT TO authenticated 
    USING (user_id = auth.uid() AND public.is_admin());

-- Default RLS blocks INSERT/UPDATE/DELETE implicitly. No explicit Deny policies.

-- 2. scheduled_scan_runs table
CREATE TABLE IF NOT EXISTS public.scheduled_scan_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    schedule_id uuid NOT NULL REFERENCES public.scan_schedules(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    
    qstash_message_id text NOT NULL UNIQUE,
    qstash_schedule_id text,
    scheduled_for timestamptz NOT NULL,
    
    status text NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'skipped')),
    scan_id uuid,
    error_code text,
    
    started_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    
    UNIQUE (schedule_id, scheduled_for)
);

ALTER TABLE public.scheduled_scan_runs ENABLE ROW LEVEL SECURITY;

-- RLS: Owners can view their own runs if admin
CREATE POLICY "Users can view own runs if admin" ON public.scheduled_scan_runs 
    FOR SELECT TO authenticated 
    USING (user_id = auth.uid() AND public.is_admin());

-- Default RLS blocks INSERT/UPDATE/DELETE implicitly. No explicit Deny policies.

-- 3. Scans table modifications
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS trigger_type text NOT NULL DEFAULT 'manual' CHECK (trigger_type IN ('manual', 'scheduled'));
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS schedule_id uuid REFERENCES public.scan_schedules(id) ON DELETE SET NULL;
