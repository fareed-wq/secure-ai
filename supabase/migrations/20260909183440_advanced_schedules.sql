-- Migration: Advanced Scheduled Scans
-- Description: Updates scan_mode constraint to allow 'active' (Advanced) schedules.

ALTER TABLE public.scan_schedules DROP CONSTRAINT IF EXISTS scan_schedules_scan_mode_check;
ALTER TABLE public.scan_schedules ADD CONSTRAINT scan_schedules_scan_mode_check CHECK (scan_mode IN ('passive', 'active'));
