-- Add email preferences to schedules
ALTER TABLE public.scan_schedules
ADD COLUMN email_report_enabled boolean NOT NULL DEFAULT false;

-- Add email delivery status to runs
ALTER TABLE public.scheduled_scan_runs
ADD COLUMN email_status text NOT NULL DEFAULT 'not_requested' CHECK (email_status IN ('not_requested', 'pending', 'sending', 'sent', 'failed')),
ADD COLUMN email_sent_at timestamptz NULL,
ADD COLUMN email_error_code text NULL,
ADD COLUMN email_lease_until timestamptz NULL;

-- Change FK to ON DELETE SET NULL so completed runs survive schedule deletion
ALTER TABLE public.scheduled_scan_runs DROP CONSTRAINT IF EXISTS scheduled_scan_runs_schedule_id_fkey;
ALTER TABLE public.scheduled_scan_runs ALTER COLUMN schedule_id DROP NOT NULL;
ALTER TABLE public.scheduled_scan_runs ADD CONSTRAINT scheduled_scan_runs_schedule_id_fkey FOREIGN KEY (schedule_id) REFERENCES public.scan_schedules(id) ON DELETE SET NULL;